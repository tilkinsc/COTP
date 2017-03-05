
del *.o
gcc -O -Wall -c *.c
gcc -o test.exe *.o -lssl -lcrypto -lgdi32

