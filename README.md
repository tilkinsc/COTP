# COTP

This module is part of a chain of OTP libraries all written in different languages. See https://github.com/OTPLibraries

A simple One Time Password (OTP) library in C/C++

Fully compatible with Authy and Google Authenticator. Full support for QR Code URI is provided. Does not support generating QR Code images.



## Libraries Recommended

In order to utilize this library, you may want the following libraries:
* OpenSSL (-lcrypto) is recommended. There are test files, which has all that setup mess already sorted out for you.


## Building

The tests use OpenSSL with `-lcrypto` for cryptographic functions.

This library works with C++, but is targeted at C. I made a .hpp header that wraps the C functions, which I find gross. Feel free to clean it up and do a pull request. I do, however, have to recommend you use the .hpp header due to namespace flooding.

See the [build.bat](build.bat) file for guidance. If you don't want to use the .hpp C++ wrapper, you can `extern "C" #include "cotp.h"` which will flood your global space with the header file contents.


## Usage

This library allows you to create a function in a specified format to communicate with the OTP generation. You will have to manually do the cryptographic functions and time returning function for TOTP, which is easy in OpenSSL; I suggest it just for that. See the test files for pre-made functions that will hook you up.

1. Create OTPData with the required information using *otp_new().
2. Create a COTP_ALGO function which SHA1/256/512's then HMAC's its input and returns 0 for error or the result length
3. Create a COTP_TIME function which returns a uint64_t that is the current time. Seconds or (recommended) milliseconds.
4. Invoke the functions you need and pass your OTPData structure pointer.

_____________

## License

This library is licensed under MIT.

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)


## Security Concerns

* otp_random_base32 uses the unsecure rand() to generate random base32 characters. A secure time is a must. Prioritize using milliseconds as your seed. Otherwise, please roll your own base32 standard compliant generator. Having multiple consumers with the same base32 secret key is not ideal. For example, if 10 accounts were made at the same second and you are using seconds to seed rand, then you end up having 10 users with 10 same base32 secret keys. Since this library suggests you use openssl, there may be convenience functions while we flush out a solution.


## TODO

* SHA256 needs to be verified if its working fully
* SHA512 needs to be verified if its working fully
