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
text_bytes_lines = st.lists(text_bytes).map(lambda s: b'\n'.join(s))

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
