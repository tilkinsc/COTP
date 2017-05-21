
REM We don't need old O files for example because sometimes breaks happen that persist when no error
del *.o

@echo off

REM Build the C dependancies, and the program, first
echo Building C
gcc -O0 -g3 -Wall -c ../*.c main.c
gcc -O0 -g3 -Wall -o test_c.exe base32.o cotp.o main.o -lcrypto -lgdi32

REM Build the C++ application after
echo Building C++
g++ -O0 -g3 -Wall -c main.cpp
g++ -O0 -g3 -Wall -o test_c++.exe base32.o cotp.o main.o -lcrypto -lgdi32

