
@echo off

REM Build the C dependencies, and the program, first
echo Building C
gcc -O0 -g3 -Wall -c ../*.c main.c
gcc -O0 -g3 -Wall -o test_c.exe otpuri.o cotp.o main.o -lcrypto -lgdi32

REM Build the C++ application after
echo Building C++
g++ -O0 -g3 -Wall -c main.cpp
g++ -O0 -g3 -Wall -o test_c++.exe otpuri.o cotp.o main.o -lcrypto -lgdi32

