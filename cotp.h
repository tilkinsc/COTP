
#pragma once

#include <stdlib.h>

/*
	Default characters used in BASE32 digests.
	For use with otp_random_base32()
*/
static const char otp_DEFAULT_BASE32_CHARS[32] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5',
	'6', '7'
};


/*
	Definitions which may be used
	
	BITS - the amount of bits SHA version generates
	BYTES - the amount of bytes SHA version generates
	DIGEST - the name, in string, of the algorithm
*/
static const int SHA1_BITS   = 160;
static const int SHA256_BITS = 256;
static const int SHA512_BITS = 512;

static const int SHA1_BYTES   = 160 / 8;	// 20
static const int SHA256_BYTES = 256 / 8;	// 32
static const int SHA512_BYTES = 512 / 8;	// 64

static const char SHA1_DIGEST[]   = "SHA1";
static const char SHA256_DIGEST[] = "SHA256";
static const char SHA512_DIGEST[] = "SHA512";

static const char OTP_CHARS[]  = "otp";
static const char TOTP_CHARS[] = "totp";
static const char HOTP_CHARS[] = "hotp";


/*
	Used for differentiation on which
	  method you are using. Necessary
	  when you go to generate a URI.
*/
typedef enum OTPType {
	OTP, TOTP, HOTP
} OTPType;

/*
	Should return 0 if error, > 1.
	First parameter is base32 secret key.
	Second parameter is input number as string.
	Last parameter is an output char buffer of the resulting HMAC operation.
*/
typedef int (*COTP_ALGO)(const char*, const char*, char*);

/*
	Holds data for use by the cotp module.
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
int totp_verifyi(OTPData* data, int key, unsigned int for_time, int valid_window);
int totp_verifys(OTPData* data, char* key, unsigned int for_time, int valid_window);
unsigned int totp_valid_until(OTPData* data, unsigned int for_time, size_t valid_window);
int totp_timecode(OTPData* data, unsigned int for_time);


/*
	HOTP functions
*/
int hotp_compares(OTPData* data, char* key, size_t counter);
int hotp_comparei(OTPData* data, int key, size_t counter);
int hotp_at(OTPData* data, size_t counter, char out_str[]);
int hotp_verifyi(OTPData* data, int key, size_t counter);
int hotp_verifys(OTPData* data, char* key, size_t counter);

