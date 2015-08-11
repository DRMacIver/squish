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


def squish(data, delimiter=None, separator=None):
    command = ['./bin/squish']
    if delimiter is not None:
        command.extend(['-d', delimiter])
    if separator is not None:
        command.extend(['-s', separator])
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


def naivesquish(data, delimiter=None, separator=None):
    if delimiter is None:
        delimiter = ' '
    if separator is None:
        separator = delimiter
    if not data:
        return b''
    lines = data.split(b'\n')
    records = []
    for line in lines:
        bits = line.split(delimiter)
        if len(bits) == 1:
            bits.append(b'')
        records.append(bits)


text_bytes = st.text().map(lambda s: s.encode('utf-8'))
text_bytes_lines = st.lists(text_bytes).map(lambda s: b'\n'.join(s))


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
    assert squish(input) == expected
