
del *.o

@echo off

echo Building C
gcc -O -Wall -c *.c
gcc -o test_c.exe base32.o cotp.o main.o -lcrypto -lgdi32


echo Building C++
g++ -O -Wall -c *.cpp
g++ -o test_c++.exe base32.o cotp.o main.o -lcrypto -lgdi32

