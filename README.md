# COTP
[![C/C++ CI](https://github.com/tilkinsc/COTP/actions/workflows/c-cpp.yml/badge.svg?branch=master)](https://github.com/tilkinsc/COTP/actions/workflows/c-cpp.yml)

This module is part of a chain of OTP libraries all written in different languages. See https://github.com/OTPLibraries

A simple One Time Password (OTP) library in C/C++

Fully compatible with Authy and Google Authenticator. Full support for QR Code URI is provided. Does not support generating QR Code images.


## Building

We use OpenSSL with `-lcrypto` for cryptographic functions.

For linux users, you will want to install libcrypto via `sudo apt install libssl-dev`

This library works with C++, but is targeted at C. I made a .hpp header that wraps the C functions, which I find gross. Feel free to clean it up and do a pull request. I do, however, have to recommend you use the .hpp header due to namespace flooding.

See the [build.bat](build.bat) or [build.sh](build.sh) file for self-building guidance. If you don't want to use the .hpp C++ wrapper, you can `extern "C" #include "cotp.h"` which will flood your global space with the header file contents. We have a [Makefile](Makefile) for use: `make libs` for just the library or `make all` to also build the test examples.


## Usage

This library allows you to create a function in a specified format to communicate with the OTP generation. You will have to manually do the cryptographic functions and time returning function for TOTP, which is easy in OpenSSL; I suggest it just for that. See the test files for pre-made functions that will hook you up.

1. Create OTPData with the required information using *otp_new().
2. Create a COTP_ALGO function which SHA1/256/512's then HMAC's its input and returns 0 for error or the result length
3. Create a COTP_TIME function which returns a uint64_t that is the current time in seconds.
4. Invoke the functions you need and pass your OTPData structure pointer.

_____________

## License

This library is licensed under MIT.

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)


## TODO

* SHA256 needs to be verified if it's working fully
* SHA512 needs to be verified if it's working fully
