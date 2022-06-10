#include "cotp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>

/*
	Allocates a new OTPData struct. Initializes its values.
	
	base32_secret is a base32 compliant secret string
	bits is the bit length of the out of the chosen hmac cryptographic algorithm
	algo is the hmac algorithm implementation for hash and hmac
	digest is the string name of the hmac algorithm
	digits is the amount of output numbers for the OTP
	
	Do not forget to call otp_free(...)
	
	Returns
			A pointer to a new struct OTPData struct
		error, 0
*/
OTPData* otp_new(const char* base32_secret, uint32_t bits, COTP_ALGO algo, const char* digest, uint32_t digits) {
	OTPData* data = malloc(sizeof(OTPData));
	if(data == 0)
		return 0;
	data->digits = digits ? digits : 6;
	data->interval = 0;
	data->bits = bits;
	data->count = 0;
	
	data->method = OTP;
	data->algo = algo;
	
	data->digest = &digest[0];
	data->base32_secret = &base32_secret[0];
	
	return data;
}

/*
	Allocates a new OTPData struct. Initializes its values. Extends off of otp_new.
	
	base32_secret is a base32 compliant secret string
	bits is the bit length of the out of the chosen hmac cryptographic algorithm
	algo is the hmac algorithm implementation for hash and hmac
	digest is the string name of the hmac algorithm
	digits is the amount of output numbers for the OTP
	interval is the amount of time a code is valid for in seconds
	
	Do not forget to call otp_free(...)
	
	Returns
			A pointer to a new struct OTPData struct
		error, 0
*/
OTPData* totp_new(const char* base32_secret, uint32_t bits, COTP_ALGO algo, const char* digest, uint32_t digits, uint32_t interval) {
	OTPData* data = otp_new(base32_secret, bits, algo, digest, digits);
	data->interval = interval;
	data->method = TOTP;
	return data;
}

/*
	Allocates a new OTPData struct. Initializes its values. Extends off of otp_new.
	
	base32_secret is a base32 compliant secret string
	bits is the bit length of the out of the chosen hmac cryptographic algorithm
	algo is the hmac algorithm implementation for hash and hmac
	digest is the string name of the hmac algorithm
	digits is the amount of output numbers for the OTP
	count is the current counter
	
	Do not forget to call otp_free(...)
	
	Returns
			A pointer to a new struct OTPData struct
		error, 0
*/
OTPData* hotp_new(const char* base32_secret, uint32_t bits, COTP_ALGO algo, const char* digest, uint32_t digits, uint64_t count) {
	OTPData* data = otp_new(base32_secret, bits, algo, digest, digits);
	data->method = HOTP;
	data->count = count;
	return data;
}


/*
	Frees data allocated by *otp_new(...) calls.
*/
void otp_free(OTPData* data) {
	free(data);
}

/*
	Un-base32's a base32 string stored inside an OTPData.
	
	out_str is the null-terminated output string already allocated
	
	Returns
			1 success
		error, 0
*/
int otp_byte_secret(OTPData* data, char* out_str) {
	if(out_str == NULL || strlen(data->base32_secret) % 8 != 0)
		return 0;
	int n = 5;
	for (size_t i=0; ; i++) {
		n = -1;
		out_str[i*5] = 0;
		for (int block=0; block<8; block++) {
			int offset = (3 - (5*block) % 8);
			int octet = (block*5)/8;
			
			unsigned int c = data->base32_secret[i*8 + block];
			if (c >= 'A' && c <= 'Z')
				n = c - 'A';
			if (c >= '2' && c <= '7')
				n = 26 + c - '2';
			if (n < 0) {
				n = octet;
				break;
			}
			out_str[i*5 + octet] |= -offset > 0 ? n >> -offset : n << offset;
			if (offset < 0)
				out_str[i*5 + octet + 1] = -(8 + offset) > 0 ? n >> -(8 + offset) : n << (8 + offset);
		}
		if(n < 5)
			break;
	}
	return 1;
}

/*
	Converts an integer into an 8 byte array.
	
	out_str is the null-terminated output string already allocated
	
	Returns
			1 success
		error, 0
*/
int otp_num_to_bytestring(uint64_t integer, char* out_str) {
	if(out_str == NULL)
		return 0;
	
	size_t i = 7;
	while  (integer != 0) {
		out_str[i--] = integer & 0xFF;
		integer >>= 8;
	}
	return 1;
}

/*
	Generates a valid base32 number.
	
	if len == 0, len = 16
	
	len is the (strlen of out_str) - 1
	chars is the base32 charset
	out_str is the null-terminated output string already allocated
	
	Returns
			1 on success
		error, 0

*/
int otp_random_base32(size_t len, const char* chars, char* out_str) {
	if(chars == NULL || out_str == NULL)
		return 0;
	len = len > 0 ? len : 16;
	for (size_t i=0; i<len; i++)
		out_str[i] = chars[rand()%32];
	return 1;
}


/*
	Compares a key against a generated key for a single specific timeblock.
	
	key is an null-terminated input string, a previous OTP generation, must be data->digits+1 long
	offset is a timeblock adjustment for the generated compare key
	for_time is the time the generated key will be created for
	
	Returns
			1 success
			0 no full comparison made
		error, 0
*/
int totp_compare(OTPData* data, const char* key, int64_t offset, uint64_t for_time) {
	char* time_str = calloc(data->digits+1, sizeof(char));
	if (time_str == 0) {
		return 0;
	}
	if(totp_at(data, for_time, offset, time_str) == 0) {
		free(time_str);
		return 0;
	}
	for (size_t i=0; i<data->digits; i++) {
		if(key[i] != time_str[i]) {
			free(time_str);
			return 0;
		}
	}
	free(time_str);
	return 1;
}

/*
	Generates a OTP key using the totp algorithm.
	
	for_time is the time the generated key will be created for
	offset is a timeblock adjustment for the generated key
	out_str is the null-terminated output string already allocated
	
	Returns
			1 if otp key was successfully generated
		error, 0
*/
int totp_at(OTPData* data, uint64_t for_time, int64_t offset, char* out_str) {
	return otp_generate(data, totp_timecode(data, for_time) + offset, out_str);
}

/*
	Generates a OTP key using the totp algorithm with the current, unsecure time in seconds.
	
	out_str is the null-terminated output string already allocated
	
	Returns
			1 if otp key was successfully generated
		error, 0
*/
int totp_now(OTPData* data, char* out_str) {
	return otp_generate(data, totp_timecode(data, time(NULL)), out_str);
}

/*
	Compares a key against a generated key for multiple timeblocks before and after a specific time.
	
	key is an null-terminated input string, a previous OTP generation, must be data->digits+1 long
	for_time is the time the generated key will be created for
	valid_window is the number of timeblocks a OTP should be valid for
	
	Returns
			1 success
		error, 0
*/
int totp_verify(OTPData* data, const char* key, uint64_t for_time, int64_t valid_window) {
	if(valid_window < 0) {
		return 0;
	}
	if(valid_window > 0) {
		for (int64_t i=-valid_window; i<valid_window+1; i++) {
			int cmp = totp_compare(data, key, i, for_time);
			if(cmp == 1) {
				return cmp;
			}
		}
		return 0;
	}
	return totp_compare(data, key, 0, for_time);
}

/*
	Calculate the time in seconds relative to for_time an OTP is valid for.
	
	for_time is a time in seconds
	valid_window is the number of timeblocks a OTP should be valid for
	
	Returns
			the expiration time for a code using the current OTPData configuration
*/
uint64_t totp_valid_until(OTPData* data, uint64_t for_time, int64_t valid_window) {
	return for_time + (data->interval * valid_window);
}

/*
	Generates the timeblock for a time in seconds.
	
	Timeblocks are the amount of intervals in a given time. For example,
	if 1,000,000 seconds has passed for 30 second intervals, you would get
	33,333 timeblocks (intervals), where timeblock++ is effectively +30 seconds.
	
	for_time is a time in seconds to get the current timeblocks
	
	Returns
			timeblock given for_time, using data->interval
		error, 0
*/
uint64_t totp_timecode(OTPData* data, uint64_t for_time) {
	if(data->interval <= 0)
		return 0;
	return for_time/data->interval;
}


/*
	Compares a key against a generated key for a single counter.
	
	key is an null-terminated input string, a previous OTP generation, must be data->digits+1 long
	offset is a timeblock adjustment for the generated compare key
	for_time is the time the generated key will be created for
	
	Returns
			1 success
			0 no full comparison made
		error, 0
*/
int hotp_compare(OTPData* data, const char* key, uint64_t counter) {
	char* cnt_str = calloc(data->digits+1, sizeof(char));
	if(cnt_str == 0)
		return 0;
	if(hotp_at(data, counter, cnt_str) == 0) {
		free(cnt_str);
		return 0;
	}
	for (size_t i=0; i<data->digits; i++) {
		if(key[i] != cnt_str[i]) {
			free(cnt_str);
			return 0;
		}
	}
	free(cnt_str);
	return 1;
}

/*
	Generates a OTP key using the hotp algorithm.
	
	counter is the counter the generated key will be created for
	out_str is the null-terminated output string already allocated
	
	Returns
			1 if otp key was successfully generated
		error, 0
*/
int hotp_at(OTPData* data, uint64_t counter, char* out_str) {
	return otp_generate(data, counter, out_str);
}

/*
	Generates a OTP key using the hotp algorithm and advances the counter.
	
	out_str is the null-terminated output string already allocated
	
	Returns
			1 if otp key was successfully generated
		error, 0
*/
int hotp_next(OTPData* data, char* out_str)
{
	return otp_generate(data, data->count++, out_str);
}

/*
	Generates a one time password given data as instructions, input as data,
	and out_str as output. Input should be > 0. out_str's size should be
	precomputed and null-terminated. If out_str is null, nothing is wrote
	to it.
	
	Returns
			> 0 OTP for the current input based off struct OTPData
		if out_str != 0, writes generated OTP as string to out_str
		error, 0 oom or failed to generate anything based off data in OTPData
	
	// TODO: check out making input unsigned, and avoid having to
	//   do checks on a string rather than a digit. Original implementation
	//   of github.com/pyotp/pyotp does string comparison and a very expensive
	//   string checking. It isn't totally necessary to do depending on the
	//   low security requirements - as long as the login checks are limited
	//   absolutely no hacking is possible. Hacking SHA is impossible anyways
	//   especially with this method, as there is no way to tell if a SHA
	//   key generation is valid for the given input or just a temp collision.
	//   Should make new functions for this though.
*/
int otp_generate(OTPData* data, int64_t input, char* out_str) {
	uint64_t code = 0;
	
	char* byte_string = 0;
	char* byte_secret = 0;
	char* hmac = 0;
	
	// de-BASE32 sizes
	uint64_t desired_secret_len = (strlen(data->base32_secret) / 8) * 5;
	
	// de-SHA size
	int bit_size = data->bits / 8;
	
	// space for OTP byte secret de-BASE32
	// space for converting input to byte string
	// space for de-SHA
	// de-BASE32, convert to byte string, de-SHA
	byte_string = calloc(8+1, sizeof(char));
	byte_secret = calloc(desired_secret_len+1, sizeof(char));
	hmac = calloc(bit_size+1, sizeof(char));
	if(byte_string == 0
			|| byte_secret == 0
			|| hmac == 0
			|| otp_num_to_bytestring(input, byte_string) == 0
			|| otp_byte_secret(data, byte_secret) == 0
			|| (*(data->algo))(byte_secret, byte_string, hmac) == 0)
		goto exit;
	
	// gather hmac's offset, piece together code
	uint64_t offset = (hmac[bit_size-1] & 0xF);
	code =
		((hmac[offset] & 0x7F) << 24 |
		(hmac[offset+1] & 0xFF) << 16 |
		(hmac[offset+2] & 0xFF) << 8 |
		(hmac[offset+3] & 0xFF));
	code %= (uint64_t) pow(10, data->digits);
	
	// write out the char array code, if requested
	if(out_str != NULL)
		sprintf(out_str, "%0*llu", data->digits, code);
	
exit:
	free(hmac);
	free(byte_string);
	free(byte_secret);
	return 1;
}


