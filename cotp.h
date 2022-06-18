#pragma once

#include <stdlib.h>
#include <stdint.h>


#define OTP_OK		(1)
#define OTP_ERROR	(0)


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
	Used for differentiation on which
	  method you are using. Necessary
	  when you go to generate a URI.
*/
typedef enum OTPType {
	OTP, TOTP, HOTP
} OTPType;

const char* OTPType_asString(OTPType type);


/*
	Must compute HMAC using passed arguments,
	  output as char array through output.
	
	key is base32 secret key.
	input is input number as string.
	output is an output char buffer of the resulting HMAC operation.
	
	Must return 0 if error, or the length in bytes of the HMAC operation.
*/
typedef int (*COTP_ALGO)(const char* key, const char* input, char* output);

/*
	Must return the current time in seconds.
*/
typedef uint64_t (*COTP_TIME)();


/*
	Holds data for use by the cotp module.
	
	If you know what you are doing,
		feel free to initialize this yourself.
*/
typedef struct OTPData {
	uint32_t digits;
	uint32_t interval; // TOTP exclusive
	uint64_t count;
	
	OTPType method;
	COTP_ALGO algo;
	COTP_TIME time;
	
	const char* base32_secret;
} OTPData;


/*
	Struct initialization functions
*/
OTPData* otp_new(const char* base32_secret, COTP_ALGO algo, uint32_t digits);
OTPData* totp_new(const char* base32_secret, COTP_ALGO algo, COTP_TIME time, uint32_t digits, uint32_t interval);
OTPData* hotp_new(const char* base32_secret, COTP_ALGO algo, uint32_t digits, uint64_t count);

/*
	OTP free function
*/
void otp_free(OTPData* data);

/*
	OTP functions
*/
int otp_generate(OTPData* data, uint64_t input, char* out_str);
int otp_byte_secret(OTPData* data, char* out_str);
int otp_num_to_bytestring(uint64_t integer, char* out_str);
int otp_random_base32(size_t len, const char* chars, char* out_str);


/*
	TOTP functions
*/
int totp_compare(OTPData* data, const char* key, int64_t offset, uint64_t for_time);
int totp_at(OTPData* data, uint64_t for_time, int64_t offset, char* out_str);
int totp_now(OTPData* data, char* out_str);
int totp_verify(OTPData* data, const char* key, uint64_t for_time, int64_t valid_window);
uint64_t totp_valid_until(OTPData* data, uint64_t for_time, int64_t valid_window);
uint64_t totp_timecode(OTPData* data, uint64_t for_time);


/*
	HOTP functions
*/
int hotp_compare(OTPData* data, const char* key, uint64_t counter);
int hotp_at(OTPData* data, uint64_t counter, char* out_str);
int hotp_next(OTPData* data, char* out_str);

