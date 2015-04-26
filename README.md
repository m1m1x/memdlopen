#memdlopen

## Description

memdlopen is a proof of concept that demonstrate the possibility to fully load a dynamic library from memory on 64 bits linux systems.
To achieve this goal, runtime code patching within the process is performed in order to hook the following functions in the ld memory space : 
* open
* lseek
* read
* mmap
* fstat
* close

This code implements methods described in Nologin's paper (www.nologin.org/Downloads/Papers/remote-library-injection.pdf).

## Compilation

$ mkdir build

$ cmake /path/to/memdlopen

$ make

## Examples

### load library from a file
$ ./memdlopen -f libexample.so

### load library from network
$ ./memdlopen -l 8888

$ nc -w 1 127.0.0.1 8888 < libexample.so 

## Limitations
* only tested on debian 8.0 (ld-2.19.so)
* for now, this code will only work on x86_64 systems 
