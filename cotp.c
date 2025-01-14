#include "cotp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <openssl/rand.h>

/*
	Converts an OTPType enum to string.
	
	Returns
			OTPType as string
		error, 0
*/
const char* OTPType_asString(OTPType type)
{
	switch (type)
	{
		case OTP: return "OTP";
		case TOTP: return "TOTP";
		case HOTP: return "HOTP";
	}
	return NULL;
}

/*
	Initializes an OTPData structure.
	
	OTPData is a non-initialized structure
	base32_secret is a base32 compliant secret string
	algo is the hmac algorithm implementation for hash and hmac
	digits is the amount of output numbers for the OTP
	
	Only call otp_free(...) if you malloc/calloc'd the OTPData* structure
	
	Returns
			The same pointer passed through data
		error, 0
*/
OTPData* otp_new(OTPData* data, const char* base32_secret, COTP_ALGO algo, uint32_t digits)
{
	data->digits = digits ? digits : 6;
	data->interval = 0;
	data->count = 0;
	
	data->method = OTP;
	data->algo = algo;
	data->time = NULL;
	
	data->base32_secret = &base32_secret[0];
	
	return data;
}

/*
	Initializes an OTPData structure. Extends off of otp_new.
	
	OTPData is a non-initialized structure
	base32_secret is a base32 compliant secret string
	algo is the hmac algorithm implementation for hash and hmac
	digits is the amount of output numbers for the OTP
	interval is the amount of time a code is valid for in seconds
	
	Only call otp_free(...) if you malloc/calloc'd the OTPData* structure
	
	Returns
			The same pointer passed through data
		error, 0
*/
OTPData* totp_new(OTPData* data, const char* base32_secret, COTP_ALGO algo, COTP_TIME time, uint32_t digits, uint32_t interval)
{
	OTPData* tdata = otp_new(data, base32_secret, algo, digits);
	tdata->interval = interval;
	tdata->time = time;
	tdata->method = TOTP;
	
	return data;
}

/*
	Initializes an OTPData structure.
	
	OTPData is a non-initialized structure
	base32_secret is a base32 compliant secret string
	algo is the hmac algorithm implementation for hash and hmac
	digits is the amount of output numbers for the OTP
	count is the current counter
	
	Only call otp_free(...) if you malloc/calloc'd the OTPData* structure
	
	Returns
			A pointer to a new struct OTPData struct
		error, 0
*/
OTPData* hotp_new(OTPData* data, const char* base32_secret, COTP_ALGO algo, uint32_t digits, uint64_t count)
{
	OTPData* hdata = otp_new(data, base32_secret, algo, digits);
	hdata->method = HOTP;
	hdata->count = count;
	
	return data;
}


/*
	Semantic convenience method.
	Equivalent to free(data).
*/
void otp_free(OTPData* data)
{
	free(data);
}

/*
	Un-base32's a base32 string stored inside an OTPData.
	
	out_str is the null-terminated output string already allocated
	
	Returns
			1 success
		error, 0
*/
COTPRESULT otp_byte_secret(OTPData* data, char* out_str) {
	if (out_str == NULL || strlen(data->base32_secret) % 8 != 0) {
		return OTP_ERROR;
	}
	
	size_t base32_length = strlen(data->base32_secret);
	size_t num_blocks = base32_length / 8;
	size_t output_length = num_blocks * 5;
	
	if (output_length == 0) {
		return OTP_OK;
	}
	
	int valid = 1;
	
	for (size_t i = 0; i < num_blocks; i++) {
		unsigned int block_values[8] = { 0 };
		
		for (int j = 0; j < 8; j++) {
			char c = data->base32_secret[i * 8 + j];
			unsigned int value = (unsigned char) c < 256 ? OTP_DEFAULT_BASE32_OFFSETS[(unsigned char) c] : -1;
			block_values[j] = value & 31;
			valid &= (value >= 0);
		}
		
		out_str[i * 5] = (block_values[0] << 3) | (block_values[1] >> 2);
		out_str[i * 5 + 1] = (block_values[1] << 6) | (block_values[2] << 1) | (block_values[3] >> 4);
		out_str[i * 5 + 2] = (block_values[3] << 4) | (block_values[4] >> 1);
		out_str[i * 5 + 3] = (block_values[4] << 7) | (block_values[5] << 2) | (block_values[6] >> 3);
		out_str[i * 5 + 4] = (block_values[6] << 5) | block_values[7];
	}

	return valid ? OTP_OK : OTP_ERROR;
}

/*
	Converts an integer into an 8 byte array.
	
	out_str is the null-terminated output string already allocated
	
	Returns
			1 success
		error, 0
*/
COTPRESULT otp_num_to_bytestring(uint64_t integer, char* out_str)
{
	if (out_str == NULL)
		return OTP_ERROR;
	
	size_t i = 7;
	while  (integer != 0)
	{
		out_str[i] = integer & 0xFF;
		i--;
		integer >>= 8;
	}
	
	return OTP_OK;
}

/*
	Generates a valid secured random base32 string.
	
	if len <= 0, len = 16
	
	len is the (strlen of out_str) - 1
	chars is the base32 charset
	out_str is the null-terminated output string already allocated
	
	Returns
			1 on success
		error, 0

*/
COTPRESULT otp_random_base32(size_t len, char* out_str)
{
	if (out_str == NULL)
		return OTP_ERROR;
	
	len = len > 0 ? len : 16;
	
	unsigned char rand_buffer[len];
	if (RAND_bytes(rand_buffer, len) != 1)
		return OTP_ERROR;
	
	for (size_t i=0; i<len; i++)
	{
		out_str[i] = OTP_DEFAULT_BASE32_CHARS[rand_buffer[i] % 32];
	}
	
	return OTP_OK;
}


/*
	Compares a key against a generated key for
	  a single specific timeblock.
	
	key is an null-terminated input string, a previous OTP generation, must be data->digits+1 long
	offset is a timeblock adjustment for the generated compare key
	for_time is the time the generated key will be created for
	
	Returns
			1 success
			0 no full comparison made
		error, 0
*/
COTPRESULT totp_compare(OTPData* data, const char* key, int64_t offset, uint64_t for_time)
{
	char time_str[data->digits+1];
	memset(time_str, 0, data->digits+1);
	
	if (totp_at(data, for_time, offset, time_str) == 0)
		return OTP_ERROR;
	
	int invalid = 0;
	for (size_t i=0; i<data->digits; i++)
	{
		invalid |=  key[i] ^ time_str[i];
	}
	if (invalid != 0)
		return OTP_ERROR;
	
	return OTP_OK;
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
COTPRESULT totp_at(OTPData* data, uint64_t for_time, int64_t offset, char* out_str)
{
	return otp_generate(data, totp_timecode(data, for_time) + offset, out_str);
}

/*
	Generates an OTP key using the totp algorithm with
	  the current timestep.
	
	out_str is the null-terminated output string already allocated
	
	Returns
			1 if otp key was successfully generated
		error, 0
*/
COTPRESULT totp_now(OTPData* data, char* out_str)
{
	return otp_generate(data, totp_timecode(data, data->time()), out_str);
}

/*
	Generates an OTP key using the totp algorithm with
	  the current timestep + 1.
	
	out_str is the null-terminated output string already allocated
	
	Returns
			1 if otp key was successfully generated
		error, 0
*/
COTPRESULT totp_next(OTPData* data, char* out_str)
{
	return otp_generate(data, totp_timecode(data, data->time()) + 1, out_str);
}

/*
	Compares a key against a generated key for multiple
	  timeblocks before and after a specific time.
	
	key is an null-terminated input string, a previous OTP generation, must be data->digits+1 long
	for_time is the time the generated key will be created for
	valid_window is the number of timeblocks a OTP should be valid for
	
	Returns
			1 success
		error, 0
*/
COTPRESULT totp_verify(OTPData* data, const char* key, uint64_t for_time, int64_t valid_window)
{
	if (key == NULL || valid_window < 0)
		return OTP_ERROR;
	
	if (valid_window > 0)
	{
		int wins = 0;
		for (int64_t i=-valid_window; i<valid_window+1; i++)
		{
			int cmp = totp_compare(data, key, i, for_time);
			if (cmp == OTP_OK)
				wins++;
		}
		
		return (COTPRESULT) wins >= 1;
	}
	
	return totp_compare(data, key, 0, for_time);
}

/*
	Calculate the time in seconds relative to
	  for_time an OTP is valid for.
	
	for_time is a time in seconds
	valid_window is the number of timeblocks a OTP should be valid for
	
	Returns
			the expiration time for a code using the current OTPData configuration
*/
uint64_t totp_valid_until(OTPData* data, uint64_t for_time, int64_t valid_window)
{
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
uint64_t totp_timecode(OTPData* data, uint64_t for_time)
{
	if (data->interval <= 0)
		return OTP_ERROR;
	
	return for_time / data->interval;
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
int hotp_compare(OTPData* data, const char* key, uint64_t counter)
{
	if (key == NULL)
		return OTP_ERROR;
	
	char cnt_str[data->digits+1];
	memset(cnt_str, 0, data->digits+1);
	
	if (hotp_at(data, counter, cnt_str) == 0)
		return OTP_ERROR;
	
	int invalid = 0;
	for (size_t i=0; i<data->digits; i++)
	{
		invalid |=  key[i] ^ cnt_str[i];
	}
	if (invalid != 0)
		return OTP_ERROR;
	
	return OTP_OK;
}

/*
	Generates a OTP key using the hotp algorithm.
	
	counter is the counter the generated key will be created for
	out_str is the null-terminated output string already allocated
	
	Returns
			1 if otp key was successfully generated
		error, 0
*/
int hotp_at(OTPData* data, uint64_t counter, char* out_str)
{
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
	Generates an OTP (One Time Password).
	
	input is a number used to generate the OTP
	out_str is the null-terminated output string already allocated
	
	Returns
			1 if otp code was successfully generated
		error, 0
*/
COTPRESULT otp_generate(OTPData* data, uint64_t input, char* out_str)
{
	if (out_str == NULL)
		return OTP_ERROR;
	
	char byte_string[8+1];
	memset(byte_string, 0, 8+1);
	
	size_t bs_len = (strlen(data->base32_secret)/8)*5;
	char byte_secret[bs_len + 1];
	memset(byte_secret, 0, bs_len + 1);
	
	char hmac[64+1];
	memset(hmac, 0, 64+1);
	
	if (otp_num_to_bytestring(input, byte_string) == 0
			|| otp_byte_secret(data, byte_secret) == 0)
		return OTP_ERROR;
	
	int hmac_len = (*(data->algo))(byte_secret, bs_len, byte_string, hmac);
	if (hmac_len == 0)
		return OTP_ERROR;
	
	uint64_t offset = (hmac[hmac_len - 1] & 0xF);
	uint64_t code =
		(((hmac[offset] & 0x7F) << 24)
		| ((hmac[offset+1] & 0xFF) << 16)
		| ((hmac[offset+2] & 0xFF) << 8)
		| ((hmac[offset+3] & 0xFF)));
	
	static const uint64_t POWERS[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };
	code %= (uint64_t) POWERS[data->digits];
	
	sprintf(out_str, "%0*" PRIu64, data->digits, code);
	
	return OTP_OK;
}

