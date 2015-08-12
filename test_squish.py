"""Copyright (C) 2015 David R. MacIver.

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

"""

import subprocess
from hypothesis import given
import hypothesis.strategies as st
import pytest


# A corpus of inputs derived from throwing AFL at squish for a while and
# seeing what it found.
AFL_CORPUS = [
    b'\n0',
    b'\n0\n \n0000\n\n0\n \n\n0\n0\n\x15\n\n0\n \n0\n\n' +
    b'0\n \n0\n \n\n0\n0\n\x15\n\n0\n \n0\n\n0\n \n000' +
    b'0\n \n00',
    b' \n \n0',
    b'0',
    b'\n0\n1',
    b'\n\n\n\n\n0\n\n\n\n0',
    b'00000000000000000',
    b'000000000000000000000000000000' +
    b'00 000000000000000000000000000' +
    b'0000000000 0000000000000000000' +
    b'000000000000000000000000000000' +
    b'0000000 0000000000000000000000' +
    b'0000000000000',
    b'\n0\n1\n0\n1',
    b'D000\n00\n1\n00\nN00\nF\n00\n1\n00\n\x000\n' +
    b'000\nF\n00\n\x000\n00\n\x000\n000\nF\n00\n\x0000' +
    b'0\n00\n1\n00\n0\x10\n1\n000000\nF\n00\n\x0000' +
    b'0\n00\n05\n1\n10\n00',
    b'\n\n\n\n00',
    b'0000000\n10\n00000000000\n10\n    ' +
    b'  00\n00\n                      ' +
    b'      0000\n1\n1',
    b'0\n0000',
    b'015\n015\n50000000\n5010\n0',
    b'00\n+\n1\n10\n0\n1\n10\n\x000\n00\n1\n\n00\n1' +
    b'\n10\n00\n+\n1\n1\n\n\x00000000000000\n0',
    b'00\n \n ',
    b'00\n \n \n\n 0\n \n \n\n \n \n  ',
    b' 00',
    b'\n0\nC000000 \nC000000 0000\n\nC0\n0' +
    b'0',
    b'00\nI0000\n000\n\n00000\n\x800 00\n0000' +
    b'000000\n40000 \n0+0\n00 00\n 00\n00' +
    b'00000\n40\n00 00000 \n400000\n4\x7f\n0' +
    b'0 0000\n0\xff00 \n400000 \n40(000\n4\x7f' +
    b'\n00 00000000\n40000000\n00 00\n 0' +
    b'00000000\n\xff\x7f0\n\xff0 00000000\n40000' +
    b' \n0+0\n00 00\n 00\n00000000\n\xff0000' +
    b'0000',
    b'0\n\n\n\n\n\n\n\n\n\n00',
    b'00\n\n\n\n\n\n0\n\n\n\n\n\n\n\n\n\n\n\xff00 000000' +
    b'00\n0000000\n\n\n\n\n\n\n\n\n\n\n\n0\n\n\n\n\n\n\n' +
    b'\n\n\n\n\xff00 000000 00000000\n0',
    b'\n0\n0\n1',
    b'000\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n0',
    b'00\n,0000\n\n0\n 0\n\n0\n \n0\n \n\n0\n0\n\x15' +
    b'\n\n0\n \n0\n\n0\n\n\n0\n1\n0\n\n0\n \n0\n\n0\n ' +
    b'\n0\n \n0\n\n0\n\n\n00\n \n0\n\n0\n\n\n0\n1\n0\n' +
    b'\n0\n \n0\n\n0\n \n0\n \n0\n\x15\n\n0\n \n0\n\n0\n' +
    b' \n0\n \n\n0\n0\n\x15\n\n0\n \n0\n\n0\n \n0000',
    b'0\n0\n',
    b'0\n\x07\n0\n\x0700\n000',
    b'00\n000\n00\n\xb101\xdc\xdc\xdc000\n\xb101\xdc\xdc\xdc\xdc\xdc0\n' +
    b'\xb101\xdc\xdc\xdc\xdc\xdc\xdc\xdc\xdc\xdc\xdc\n\xb101\xdc\xdc\xdc' +
    b'\xdc\xdc\xdc\xdc\xdc\xdc\xdc00\n' +
    b'00\n1\n1',
    b'0\n0\n1',
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000',
    b'\n0\n \n0',
    b'0\n10\n0\n1',
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000 00' +
    b'000000000000000000000000000000' +
    b'000000000',
    b'\n00\n00',
    b'\n000\n 000 \n\n00\n \n \n \n\n 0\n \n \n\n' +
    b' \n \n00000\n \n \n \n\n \n\n \n\n \n\n00\n ' +
    b'\n \n 0\n \n \n\n \n\n \n\n \n\n\n 0\n \n \n\n ' +
    b' \n \n 0\n \n\n 0\n \n \n\n \n\n \n  ',
    b'00 ',
    b'\n \n\n \n 0',
    b'\n\n<0\n0',
    b'0\n',
    b'00\n,00000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'0000000',
    b'0000\n1\n000\n1\n1\n000\n1\n\x190\n00\n1\n1' +
    b'\n00\n1\n\x190\n00\n1\n10\n0000\n\x10\n1\n1',
    b'\n0 ',
    b'00000000 00000 00  00000000000' +
    b' 000 000 000000 00',
    b'\n\n00000\n 000 \n\n00\n \n \n \n\n 0\n \n' +
    b' \n\n \n \n 0\n00\n \n\n 0\n \n \n \n\n \n\n0' +
    b'0\n \n \n \n\n 0\n \n \n\n  \n \n 0\n \n\n 0' +
    b'\n \n \n\n \n\n \n  ',
    b' 000000\n \n \n\n \n \n 0000\n 0\n \n \n' +
    b'\n  \n \n 0 0\n \n \n\n \n\n \n  ',
    b'\n0\n',
    b'0\n0',
    b'0 000000',
    b'00\n00\n1\n100\n00\n1\n10 00\n\n10\n00\n' +
    b'1\n10 00\n\n10\n00\n1\n1\n\n10\n00\n1\n10' +
    b' 00\n\n10\n00\n1\n10',
    b'000\n\n000000000\n\n000000\n\n0',
    b'00000\n1\n1000\n1 00000\n0000\n1\n10' +
    b'00\n1 00\n0000000\n\x000\n 00000\n00\n ',
    b'00\n0\n00\n 0\n 00  0\n 0 0   \n 0 0' +
    b'\n 0 0   \n0\n0',
    b'B0\n0000000\n10\n1\n10\n0000\n\x0000\n00' +
    b'\n\x0000\n0000\n30\n000 00\n10\n000\n100' +
    b'0\n1\n000\n10\n\n1\n1',
    b'\x0e0\n0000\n0\x0e00000\n40\n00 00\n40000' +
    b' 00000000\n0\x0e0\n00 0000000000000' +
    b'0 00000000\n4',
    b'000 00 0 0 ',
    b'000000000000000000000000000000' +
    b'000',
    b'00\n10',
    b'00\n00\n1\n10\n00\n1\n1',
    b'000 00000000',
    b'00\n\n0\n\n0',
    b'00\n \n \n\xfd 0\n0\n \n \n 00\n \n 0000\n\n' +
    b'00000 \n 0\n \n00\n 0 0\n \n00\n.\n 00' +
    b'00\n\n\n \n \n 00\n\n 0000 ',
    b'0000000\n\xed0\n0\n\n1\n0',
    b'\n0\n \n0',
    b'00\n00\nG\n00\n1000\n1 000\n\x000\n00\nG\n' +
    b'00\n1\n10\n1 \n000\nG\n00\n1\n10\n1 \n00' +
    b'\n100',
    b'000',
    b'000000000',
    b' 0\n \n \n\n 0\n \n \n\n \n \n  ',
    b'0000',
    b'0\n1',
    b' 0 000000000 000000',
    b'\n0 ',
    b'00\n\r0\n0000',
    b'00\n\n0000000\n\x1c0\n\n0000\n\x1c10\n\x1c10\n\x1c' +
    b'00000000\n\n000000000\n\n00000\n\n00',
    b'0\n0\n0\n\n0',
    b'\n \n \n',
    b'0000\n\xeb00000000000 0\n0000\xc2\xc2\xc2\xc200' +
    b'000000000000000 000\n0000\xc2\xc2\xc2\xc2\xc20' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'0000000000000000000000000\n7000' +
    b'0000\n0',
    b'00\n0\n00\n\xb1010000000000\n\xb10100000' +
    b'000000000\n00\n1\n1',
    b'\n0000',
    b'000\n 0\n0\n 0\n',
    b'00000',
    b'\xff\n00000000000000000',
    b'00000   0000 00000            ' +
    b'000000000000000000',
    b' 00000000\n000000000',
    b'\x7f0\n00000000\n000"\n0Q0000\n"00000' +
    b'\n00\n\xff00\n000000\n<00\n0000000',
    b'0000\n\x030000000\n\xff0000000\n0000\n\x1b0' +
    b'00\n000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'00000 0000000000000000\n1<0<000' +
    b'\n1<0000000000000\n1\n00000000000' +
    b'0000000000\n1\n0',
    b'0\n\n0',
    b'\n0\n',
    b'  ',
    b'\n100\n10\n\n1\n10\n00',
    b'00 000',
    b'\n000\n0t00000000000000000000000' +
    b'0000000',
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'0000000000000000000',
    b'0\n0\n000000\n00\x140000\n0',
    b'\n0\n0',
    b'\n0\n\n0000\n\n\n\xed\n00\n\n0\n\n0\n\n0\n\n\n\n00' +
    b'00\n\n0\n\xff\n\n0\n\n0\n\n\n\n\n00\n\n\n\n0\n\xff\n\n\n' +
    b'\n\n0\n\n\n\n00\n\n\n\n\n0\n\xff\n\n0\n\n0000',
    b'0 0',
    b'00\nP\n0',
    b'\n',
    b'0000000000000000\nF\n00\nU0\n00\nF\n' +
    b'00\n0/00\nd\n00000\n\n0000\n\n\n\n\n\n\n\n\n' +
    b'0\n\n000\n\n\n000000\n\n\n\n\n\n\n\n\n0\n\n000' +
    b'0000\n\n000000\n\n\n00',
    b'00\n,00000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000000000000000000000' +
    b'000000000000 0',
]


def squish(data, delimiter=None, terminator=None):
    command = ['./bin/squish']
    if delimiter is not None:
        command.extend(['-d', delimiter])
    if terminator is not None:
        command.extend(['-t', terminator])
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    process.stdin.write(data)
    process.stdin.close()
    result = process.stdout.read()
    process.wait()
    if process.returncode:
        raise ValueError('Return code %d' % (process.returncode,))
    return result


def naivesquish(data, delimiter=None, terminator=None):
    if delimiter is None:
        delimiter = b' '
    if terminator is None:
        terminator = b'\n'
    if not data:
        return b''

    def key_for(line):
        return line.split(delimiter, 1)[0]

    lines = data.split(terminator)
    results = [lines[0]]
    current_key = key_for(lines[0])
    for line in lines[1:]:
        line_key = key_for(line)
        if line_key == current_key:
            results[-1] += line[len(current_key):]
        else:
            results.append(line)
            current_key = line_key
    return terminator.join(results)

text_bytes = st.text().map(lambda s: s.encode('utf-8'))
text_bytes_lines = st.lists(text_bytes).map(lambda s: b'\n'.join(s)) | \
    st.sampled_from(AFL_CORPUS)

charoption = st.integers(
    min_value=1, max_value=255).map(lambda i: bytes([i])) | st.none()


@given(text_bytes_lines, charoption, charoption)
def test_squish_is_equal_to_reference_implementation(xs, s, d):
    assert squish(xs, s, d) == naivesquish(xs, s, d)


@given(text_bytes_lines)
def test_default_squish_is_idempotent(xs):
    t = squish(xs)
    assert squish(t) == t


@given(text_bytes_lines)
def test_squished_is_not_longer(xs):
    t = squish(xs)
    assert len(t) <= len(xs)


@given(text_bytes_lines)
def test_does_not_remove_any_characters(xs):
    realchars = set(xs)
    realchars.discard(ord(b'\n'))
    realchars.discard(ord(b' '))
    assert realchars.issubset(set(squish(xs)))


@given(text_bytes_lines)
def test_does_not_contain_any_duplicate_lines(xs):
    ls = squish(xs).split(b'\n')
    for u, v in zip(ls, ls[1:]):
        assert u != v


@pytest.mark.parametrize(
    ('input',), [(x,) for x in AFL_CORPUS]
)
def test_matches_on_whole_corpus(input):
    assert naivesquish(input) == squish(input)


@pytest.mark.parametrize(
    ('input', 'expected'), [
        (b'', b''),
        (b'\n', b''),
        (b'0\n0', b'0'),
        (b'0\n0\n', b'0\n'),
        (b'0\n0\n1', b'0\n1'),
        (b'\n0\n0\n1', b'\n0\n1'),
        (b'\n0\n', b'\n0\n'),
        (b'\n0 ', b'\n0 '),
        (b'\n0\n \n0', b'\n0\n \n0'),
        (b'\n0\n0', b'\n0'),
    ]
)
def test_standard_examples(input, expected):
    assert naivesquish(input) == expected
    assert squish(input) == expected
