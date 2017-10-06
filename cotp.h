
#pragma once

#include <stdlib.h>

/*
	Default characters used in BASE32 digests.
	For use with otp_random_base32()
*/
static const char otp_DEFAULT_CHARS[32] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5',
	'6', '7'
};


/*
	Used for differentiation on which
	  method you are using. Necessary
	  when you go to generate a URI.
*/
typedef enum OTPType {
	OTP, TOTP, HOTP
} OTPType;

/*
	Should return 0 if error, > 0 if no error.
	First parameter is base32 secret key.
	Second parameter is input number as string.
	Last parameter is an output char buffer of the resulting HMAC operation.
*/
typedef int (*COTP_ALGO)(const char*, const char*, char*);

/*
	Holds data for use by the cotp module.
	
	The algorithm should take argument 1(key) and
	  argument 2(value) and encrypt/sha/whatever it.
	  Then you should HMAC it. Then you should store
	  the results in argument 3, which is predefined size
	  with the given bits int provided in the init.
	
	The bits assumes 8 bits per byte. So a SHA1 would have
	  160 bits, or 20 bytes. As per a SHA256 with 256 bits,
	  or 40 bytes. That is 80 bytes for a SHA512.
	
	The interval is for totp and is a must to have. Two
	  programs generating OTPs for use, such as google auth,
	  will be out of sync if these intervals aren't the same.
	  Google authenticator uses 30.
	
	Digits is 6. This is the length of the int that gets
	  generated with otp_generate. It is 6 because that is
	  what google auth and authy assume.
	
	The digest is for the user. It isn't necessary. However,
	  you will use it in a URI to generate a QR code.
	
	The base32_secret is indeed a secret key. Only the user
	  should know this key. This key is what keeps you two
	  communicating securely. See otp_random_base32.
*/
typedef struct OTPData {
	size_t digits;
	size_t interval; // TOTP exclusive
	size_t bits;
	OTPType method;
	COTP_ALGO algo;
	
	const char* digest;
	const char* base32_secret;
} OTPData;


/*
	Struct initialization functions
*/
OTPData* otp_new(const char* base32_secret, size_t bits, COTP_ALGO algo, const char* digest, size_t digits);
OTPData* totp_new(const char* base32_secret, size_t bits, COTP_ALGO algo, const char* digest, size_t digits, size_t interval);
OTPData* hotp_new(const char* base32_secret, size_t bits, COTP_ALGO algo, const char* digest, size_t digits);

/*
	OTP free function
*/
void otp_free(OTPData* data);

/*
	OTP functions
*/
int otp_generate(OTPData* data, int input, char* out_str);
int otp_byte_secret(OTPData* data, size_t size, char* out_str);
int otp_int_to_bytestring(int integer, char* out_str);
int otp_random_base32(size_t len, const char* chars, char* out_str);


/*
	TOTP functions
*/
int totp_compares(OTPData* data, char* key, size_t increment, unsigned int for_time);
int totp_comparei(OTPData* data, int key, size_t increment, unsigned int for_time);
int totp_at(OTPData* data, unsigned int for_time, size_t counter_offset, char* out_str);
int totp_now(OTPData* data, char* out_str);
int totp_verify(OTPData* data, int key, unsigned int for_time, int valid_window);
int totp_timecode(OTPData* data, unsigned int for_time);


/*
	HOTP functions
*/
int hotp_compares(OTPData* data, char* key, size_t counter);
int hotp_comparei(OTPData* data, int key, size_t counter);
int hotp_at(OTPData* data, size_t counter, char out_str[]);
int hotp_verify(OTPData* data, int key, size_t counter);

