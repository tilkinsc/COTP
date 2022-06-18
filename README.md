# COTP

This module is part of a chain of OTP libraries all written in different languages. See https://github.com/OTPLibraries

A simple One Time Password (OTP) library in C/C++

Fully ompatible with Authy and Google Authenticator. Full support for QR code url is provided.


## Libraries Needed

In order to utilize this library, you may want the following libraries:
* OpenSSL (-lcrypto) is recommended. There is a test file which has all that mess already sorted out for you.


## Configuration

This library works with C++, but is targeted at C. I made a .hpp header that wraps the C functions, which I find gross. Feel free to clean it up and do a pull request. I do, however, have to recommend you use the .hpp header due to namespace flooding.

_____________

## License

This library is licensed under GNU General Public License v3.0.

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)


## Usage

The library allows you to create a function in a specified format to communicate with the OTP generation. You will have to manually do the cryptographic functions and time function for TOTP, which is easy in OpenSSL; I suggest it just for that. See the test file for pre-made functions that will hook you up.

1. Create OTPData with the required information using otp_new().
2. You need to memset any buffer you give to the library to get information or calloc everything.
3. Invoke functions you need and pass said OTPData.

## Building

The examples use OpenSSL with `-lcrypto` for cryptographic functions.

See the test/build.bat file for guidance. It is simply compiling all the CUs as C. If you don't want to use the .hpp C++ wrapper, you can extern "C" #include "cotp.h" which will flood your global space with the header file contents.

## TODO

* SHA256 needs verified if its working fully
* SHA512 needs verified if its working fully
