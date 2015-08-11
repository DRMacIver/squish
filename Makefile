CC=gcc --std=c99 -Iinclude

all: bin/squish

testingvenv:
	virtualenv testingvenv --python=python3
	testingvenv/bin/pip install hypothesis pytest

build/gopt.o: src/gopt.c include/gopt.h
	mkdir -p build
	$(CC) -c -o build/gopt.o src/gopt.c

bin/squish: build/gopt.o src/squish.c
	mkdir -p bin 
	$(CC) -Wall -pedantic -Werror -o bin/squish src/squish.c build/gopt.o

clean:
	rm -rf build bin

test: bin/squish testingvenv
	./testingvenv/bin/python -m pytest test_squish.py

install: bin/squish
	cp doc/squish.man /usr/local/man/man1/squish.1
	install bin/squish /usr/bin/squish 
