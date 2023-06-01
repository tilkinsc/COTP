@echo off

IF EXIST "log_c.txt" del log.txt
IF EXIST "log_c++.txt" del log.txt

test_c.exe >> log_c.txt
test_c++.exe >> log_c++.txt
