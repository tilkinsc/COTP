#!/bin/sh

echo "Compiling"
gcc -O2 -Wall -shared -fPIC -c cotp.c otpuri.c

echo "Building SO"
gcc -O2 -Wall -shared -o libcotp.so cotp.o otpuri.o  -lcrypto

echo "Building static library"
ar rcs -o libcotp.a cotp.o otpuri.o

echo "Building test C application"
gcc -O2 -Wall -L . -I . -o test_c test/main.c libcotp.a -lcrypto -lm

echo "Building test C++ application"
g++ -O2 -Wall -L . -I . -o test_cpp test/main.cpp libcotp.a -lcrypto

