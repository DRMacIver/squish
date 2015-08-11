/*
Copyright (C) 2015 David R. MacIver

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <gopt.h>

#define DEFAULT_BUFFER_SIZE 128

typedef enum {
  first_line,
  matching_key,
  building_key,
  writing_non_key,
} write_state;

typedef struct {
  FILE *output;
  write_state state;
  char *buffer;
  size_t capacity;
  size_t keysize;
  char delimiter;
  char terminator;
  size_t current_index;
} squisher;

static void squisher_init(squisher *squish, FILE *output, char delimiter,
                          char terminator) {
  squish->output = output;
  squish->delimiter = delimiter;
  squish->terminator = terminator;
  squish->capacity = DEFAULT_BUFFER_SIZE;
  squish->keysize = 0;
  squish->buffer = malloc(DEFAULT_BUFFER_SIZE);
  squish->state = first_line;
  squish->current_index = 0;
}

void squisher_debug(squisher *squish) {
  fprintf(stderr, "Squisher: state=");
  switch (squish->state) {
  case first_line:
    fprintf(stderr, "first_line");
    break;
  case matching_key:
    fprintf(stderr, "matching_key");
    break;
  case building_key:
    fprintf(stderr, "building_key");
    break;
  case writing_non_key:
    fprintf(stderr, "writing_non_key");
    break;
  }
  fprintf(stderr, ", buffer=\"");
  fwrite(squish->buffer, sizeof(char), squish->keysize, stderr);
  fprintf(stderr, "\", current_index=%d\n", (int)squish->current_index);
}

static void squisher_print_key(squisher *squish) {
  fputc(squish->terminator, squish->output);
  fwrite(squish->buffer, sizeof(char), squish->keysize, squish->output);
}

static void squisher_done(squisher *squish) {
  if (squish->state == matching_key) {
    assert(squish->current_index <= squish->keysize);
    if (squish->current_index < squish->keysize) {
      squish->keysize = squish->current_index;
      squisher_print_key(squish);
    }
  }
  free(squish->buffer);
  fclose(squish->output);
}

static void squisher_buffer_append(squisher *squish, char c) {
  assert(squish->keysize <= squish->capacity);
  if (squish->keysize == squish->capacity) {
    squish->capacity *= 2;
    squish->buffer = realloc(squish->buffer, squish->capacity);
  }
  assert(squish->keysize < squish->capacity);
  squish->buffer[squish->keysize++] = c;
}

static void squisher_write_char(squisher *squish, char c) {
  if (c == squish->terminator) {
    switch (squish->state) {
    case matching_key:
      if (squish->current_index != squish->keysize) {
        // otherwise we would have transitioned to building key
        assert(squish->current_index < squish->keysize);
        squish->keysize = squish->current_index;
        squisher_print_key(squish);
      }
    case building_key:
      squish->keysize = squish->current_index;
    default:
      squish->state = matching_key;
      break;
    }
  } else if (c == squish->delimiter) {
    if (squish->state == matching_key) {
      if (squish->current_index != squish->keysize) {
        squish->keysize = squish->current_index;
        squisher_print_key(squish);
      }
    }
    squish->state = writing_non_key;
    fputc(c, squish->output);
  } else {
    switch (squish->state) {
    case first_line:
      squisher_buffer_append(squish, c);
      fputc(c, squish->output);
      break;
    case matching_key:
      if ((squish->current_index < squish->keysize) &&
          (squish->buffer[squish->current_index] == c)) {
        break;
      } else {
        squish->keysize = squish->current_index;
        squisher_print_key(squish);
        squish->state = building_key;
      }
    case building_key:
      squisher_buffer_append(squish, c);
    case writing_non_key:
      fputc(c, squish->output);
    }
  }
  if (c == squish->terminator) {
    squish->current_index = 0;
  } else {
    squish->current_index++;
  }
}

int main(int argc, const char **argv) {
  char delimiter = ' ';
  char terminator = '\n';

  FILE *input = stdin;
  FILE *output = stdout;

  bool usage_fail = false;

  void *options = gopt_sort(
      &argc, argv,
      gopt_start(
          gopt_option('h', 0, gopt_shorts('h'), gopt_longs("help")),
          gopt_option('d', GOPT_ARG, gopt_shorts('d'), gopt_longs("delimiter")),
          gopt_option('t', GOPT_ARG, gopt_shorts('t'), gopt_longs("terminator")),
          gopt_option('o', GOPT_ARG, gopt_shorts('o'), gopt_longs("output"))));

  if (gopt(options, 'h')) {
    puts("Usage: squish [options] [target]");
    puts("Options are:");
    puts("  -h, --help: You're looking at it");
    puts("  -d, --delimiter: Specify the character that marks the end of the "
         "initial key. Defaults to ' '");
    puts("  -o, --output: The file to write output to. Defaults to stdout");

    exit(0);
  }

  const char *long_delimiter = NULL;
  if (gopt_arg(options, 'd', &long_delimiter)) {
    if (strlen(long_delimiter) != 1) {
      fprintf(stderr, "squish: delimiter must be a single character\n");
      usage_fail = true;
    }

    delimiter = long_delimiter[0];
  }

  const char *long_terminator = NULL;
  if (gopt_arg(options, 't', &long_terminator)) {
    if (strlen(long_terminator) != 1) {
      fprintf(stderr, "squish: terminator must be a single character\n");
      usage_fail = true;
    }

    terminator = long_terminator[0];
  }

  if (argc > 2) {
    fprintf(stderr, "squish: Too many arguments: ");
    for (int i = 1; i < argc; i++) {
      fprintf(stderr, "%s ", argv[i]);
    }
    fprintf(stderr, "\n");
    usage_fail = true;
  }

  if (argc == 2) {
    input = fopen(argv[1], "r");
    if (!input) {
      fprintf(stderr, "squish: Could not open input file %s for reading\n",
              argv[1]);
      usage_fail = true;
    }
  }

  const char *output_file = NULL;
  if (gopt_arg(options, 'o', &output_file) && strcmp(output_file, "-") &&
      !usage_fail) {
    output = fopen(output_file, "w");
    if (!output) {
      fprintf(stderr, "squish: Could not open output file %s for writing\n",
              output_file);
      usage_fail = true;
    }
  }

  gopt_free(options);

  if (usage_fail)
    exit(1);

  squisher squish;
  squisher_init(&squish, output, delimiter, terminator);
  int c;
  while (true) {
    c = fgetc(input);
    if (c == EOF) {
      squisher_done(&squish);
      break;
    } else {
      squisher_write_char(&squish, c);
    }
  }

  return 0;
}
