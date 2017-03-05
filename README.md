= COTP =

This library works with C++, but is targeted at C. I made a .hpp header that wraps the C functions, which I find gross. Feel free to clean it up and do a pull request.

COTP stands for C One Time Library. It is a simple library which allows you to check and generate OTPs for applications who need verification. This project is spun off of my LuaOTP project here on github. LuaOTP was inspired by PyOTP made by pyotp on github. If you do not know how OTP/TOTP/HOTP works, you should look at pyotp as their readme.md is more comprehensive.

This module works with Authy and Google Authenticator.

The code needs cleaned up some. The otp_generate function is kinda iffy because it can return an int instead of the proper string. The proper string is in accordance with the other languages. There really is no use for the string version. Mind your memsets. You need to memset any buffer you give to the library to get information.

One thing you need to mind is the bits when doing the encryption+HMAC. You should be using SHA1 because that is what is widely supported and only available from Google Authenticator (monopoly I guess). The SHA1 gives you 160 bits, or 20 bytes. See the source for for more information. Also, you may just want to check out the header anyways. Learn how this library works.

Looking at LuaOTP from COTP you can see LuaOTP and PyOTP allow building a URI to use in QR code. I want to implement it when I feel encouraged to. C isn't good for string manipulation, especially when I am trying to avoid freeing. If you want to work on it, let me know and I will accept pull requests.

The base32 compilation units are licensed by someone else under something similar to 'keep my copyright, but you can even sell this.' Please see the respective files.

== Small Overview ==

The library allows you to create a function in a specified format to communicate with the OTP generation. You will have to manually do the cryptographic functions, which is easy in OpenSSL. I suggest it just for that. Evidently there was some security concerns, but it seems like a myth because they do what they are supposed to. Anyways, you need to encrypt then HMAC the encryption.

One final note: If you want me to translate the OTP language in your language, ask.

== Building ==

The examples use OpenSSL with -lcrypto and -lgdi32 for cryptographic functions.

This was build for support with C89. See the test/build.bat file for guidance. It is simpley compiling all the CUs as C. If you don't want to use the .hpp C++ wrapper, you can extern "C" #include "cotp.h" which will flood your global space with the header file contents.
