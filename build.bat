@echo off

echo Compiling
gcc -O2 -Wall -shared -c cotp.c otpuri.c

echo Building DLL
gcc -O2 -Wall -shared -o libcotp.dll cotp.o otpuri.o

echo Building static library
ar rcs -o libcotp.a cotp.o otpuri.o

echo Building test C application
gcc -O2 -Wall -L . -I . -o test_c.exe test/main.c -lcotp -lcrypto -lgdi32

echo Building test C++ application
g++ -O2 -Wall -L . -I . -o test_c++.exe test/main.cpp -lcotp -lcrypto -lgdi32

