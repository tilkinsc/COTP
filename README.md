# COTP

This module is part of a chain of OTP libraries all written in different languages. See https://github.com/OTPLibraries

A simple One Time Password (OTP) library in C/C++

Compatible with Authy and Google Authenticator. Full support for QR code url is provided.


## Libraries Needed

In order to utilize this library, you will need the following libraries:
* OpenSSL is recommended to use with this library. There is a test file which has all that mess already sorted out for you.


## Configuration

This library works with C++, but is targeted at C. I made a .hpp header that wraps the C functions, which I find gross. Feel free to clean it up and do a pull request. I do, however, have to recommend you use the .hpp header due to namespace flooding.

Make sure you mind your memsets when using the string (byte) version of the library functions. When it comes down to it, this library will convert your integer numbers to string and do a comparison byte by byte. There is no need for expensive testing - nobody knows what is going on except the key holders and the key can't be reversed because we only send a small part of the hmac. That being said, there is no support for digits > 9 yet - as this is half an int's limit. I need to switch to longs.


## Description

This was actually a spawn off pyotp, but I would necessarily say the code was copied. Things in python aren't in C/C++, therefore I had to make the methods myself. However, credits will go to the module for providing a guideline of what to do. [Here](https://github.com/pyotp/pyotp) you can find pyotp and realize how different it really is.

_____________

## License

This library is licensed under GNU General Public License v3.0.

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)


## Usage

The library allows you to create a function in a specified format to communicate with the OTP generation. You will have to manually do the cryptographic functions, which is easy in OpenSSL. I suggest it just for that. Anyways, you need to encrypt them and HMAC the encryption. See the test file for pre-made function that hook up nicely in any environment.

One thing you need to mind is the bits when doing the encryption+HMAC. You should be using SHA1 because that is what is widely supported and only available from Google Authenticator (name-brand dominant I guess). The SHA1 gives you 160 bits, or 20 bytes. See the test source for for more information. Also, you may just want to check out the header anyways. Learn how this library works.

To use this library, pick either TOTP or HOTP then use the provided files - giving the functions what they need. The only thing you really need to pay attention is settings. Check out the test file, as it will tell you what the default requirements is for Google Authenticator, but you should always be using Authy (it is the most lenient).

You need to memset any buffer you give to the library to get information or calloc everything.

One final note: If you want me to translate the OTP language in your language, ask.

## Building

The examples use OpenSSL with `-lcrypto` and `-lgdi32` for cryptographic functions.

This was built for support with C89. See the test/build.bat file for guidance. It is simpley compiling all the CUs as C. If you don't want to use the .hpp C++ wrapper, you can extern "C" #include "cotp.h" which will flood your global space with the header file contents.

## TODO

* update comments
* make sure all includes are organized and not redundant
* ensure cotp.hpp is implemented correctly (since commit 97f7d83956be28a44246490806adc8e877a6eebc )
* switch to longs/dedicated 64bit numbers
