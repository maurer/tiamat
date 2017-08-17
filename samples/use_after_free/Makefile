CFLAGS=-fomit-frame-pointer

all: func link external.so simple safe path_sensitive remalloc

external.so: external.c
	gcc -shared -fPIC external.c -o external.so

link: external.so link.o

clean:
	rm -f func link external.so simple safe remalloc path_sensitive
