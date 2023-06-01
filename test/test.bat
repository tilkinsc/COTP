@echo off

IF EXIST "log.txt" del log.txt

test_c.exe >> log.txt
test_c++.exe >> log.txt
