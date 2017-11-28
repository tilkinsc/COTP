# COTP

This library works with C++, but is targeted at C. I made a .hpp header that wraps the C functions, which I find gross. Feel free to clean it up and do a pull request.

COTP stands for C One Time Library. It is a simple library which allows you to check and generate OTPs for applications who need verification. This project is spun off of my LuaOTP project here on github. LuaOTP was inspired by PyOTP made by pyotp on github. If you do not know how OTP/TOTP/HOTP works, you should look at pyotp/pyotp as their readme.md is more comprehensive.

This module works with Authy and Google Authenticator.

Make sure you mind your memsets when using the string (byte) version of the library functions. When it comes down to it, this library will convert your integer numbers to string and do a comparison byte by byte. There is no need for expensive testing - nobody knows what is going on except the key holders and the key can't be reversed because we only send a small part of the hmac. That being said, there is no support for digits > 9 yet - as this is half an int's limit.

Support for QR code url (for authy and google authenticator) is complete and full to specification.

## License

No external code is used. Please see the license file for licensing information.

## Usage

The library allows you to create a function in a specified format to communicate with the OTP generation. You will have to manually do the cryptographic functions, which is easy in OpenSSL. I suggest it just for that. Anyways, you need to encrypt them and HMAC the encryption. See the test file for pre-made function that hook up nicely in any environment.

One thing you need to mind is the bits when doing the encryption+HMAC. You should be using SHA1 because that is what is widely supported and only available from Google Authenticator (name-brand dominant I guess). The SHA1 gives you 160 bits, or 20 bytes. See the test source for for more information. Also, you may just want to check out the header anyways. Learn how this library works.

You need to memset any buffer you give to the library to get information or calloc everything.

One final note: If you want me to translate the OTP language in your language, ask.

## Building

The examples use OpenSSL with -lcrypto and -lgdi32 for cryptographic functions.

This was built for support with C89. See the test/build.bat file for guidance. It is simpley compiling all the CUs as C. If you don't want to use the .hpp C++ wrapper, you can extern "C" #include "cotp.h" which will flood your global space with the header file contents.
