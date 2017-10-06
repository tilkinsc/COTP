
#include "cotp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "base32.h"



/*
	Functions to initialize the data struct OTPData.
	Everything is set but the interval in only the occasion you
	  aren't using TOTP.
	base32_secret is a key in a base32 character set, see cotp.h for default chararacter set.
			
	Providing the HMAC algorithm is necessary. Only works with HMAC, unless write own compare function.
	digest is a null-terminated string stating "SHA1", which google authenticator only supports (3/4/2017)
	digits are usually always 6, which is the only thing supported by google authenticator (3/4/2017)
	
	Google authenticator only supports SHA1 with HMAC (3/4/2017)
	  You can use anything though, but must require some form to attain
	  a code, like a custom google authenticator. Also works with authy.
	  ... or even this library. You must use your own compare function.
	
	Returns a pointer (needs to be freed) to the struct of data.
*/
OTPData* otp_new(const char* base32_secret, size_t bits, COTP_ALGO algo, const char* digest, size_t digits) {
	OTPData* data = malloc(sizeof(OTPData));
	if(data == 0)
		return 0;
	data->digits = digits ? digits : 6;
	
	data->base32_secret = &base32_secret[0];
	data->digest = &digest[0];
	data->algo = algo;
	data->bits = bits;
	
	data->method = OTP;
	return data;
}

/*
	In addition to otp_new
	
	Sets the interval and method, which otp_new wasn't made to do, as these are TOTP specific.
	Calls on otp_new();
	
	Returns a pointer (needs to be freed) to the struct of data.
*/
OTPData* totp_new(const char* base32_secret, size_t bits, COTP_ALGO algo, const char* digest, size_t digits, size_t interval) {
	OTPData* data = otp_new(base32_secret, bits, algo, digest, digits);
	data->interval = interval;
	data->method = TOTP;
	return data;
}

/*
	In addition to otp_new
	
	Sets the method, which otp_new wasn't made to do, as these are HOTP specific.
	Calls on otp_new();
	
	Returns a pointer (needs to be freed) to the struct of data.
*/
OTPData* hotp_new(const char* base32_secret, size_t bits, COTP_ALGO algo, const char* digest, size_t digits) {
	OTPData* data = otp_new(base32_secret, bits, algo, digest, digits);
	data->method = HOTP;
	return data;
}


/*
	Frees memory allocated with otp_new()/totp_new()/hotp_new()
*/
void otp_free(OTPData* data) {
	free(data);
}


/*
	Generates a one time password integer as null terminated char array.
	out_str size must be at least data->digits. Does not null-terminate.
	If null is specified in argument out_str, no string will be
	  generated of the result, but the returned int is still good.
	Returns (>0)true, 0 if length of data->base32_secret % 8 != 0
	
	// TODO: check out making input unsigned
*/
int otp_generate(OTPData* data, int input, char* out_str) {
	if(input < 0) return 0;
	
	// de-BASE32
	size_t secret_len = strlen(data->base32_secret);
	size_t desired_secret_len = UNBASE32_LEN(secret_len);
	
	char* byte_secret = calloc(desired_secret_len+1, sizeof(char));
	int bs = otp_byte_secret(data, secret_len, byte_secret);
	if(bs == 0) {
		free(byte_secret);
		return 0;
	}
	
	// input into OTP standard bytestring
	char* byte_string = calloc(8+1, sizeof(char));
	otp_int_to_bytestring(input, byte_string);
	
	// convert SHA's bits into length, decryption
	int bit_size = data->bits/8;
	char* hmac = calloc(bit_size+1, sizeof(char)); // TODO: why +1
	int err = (*(data->algo))(byte_secret, byte_string, hmac);
	if(err == 0) {
		free(hmac);
		free(byte_string);
		free(byte_secret);
		return 0;
	}
	
	// gather hmac's offset, piece together code
	int offset = (hmac[bit_size-1] & 0xF);
	int code =
		(hmac[offset] & 0x7F) << 24 |
		(hmac[offset+1] & 0xFF) << 16 |
		(hmac[offset+2] & 0xFF) << 8 |
		(hmac[offset+3] & 0xFF);
	code %= (int)pow(10, data->digits);
	
	// write out the char array code, if requested
	if(out_str != NULL)
		sprintf(out_str, (char[]){'%', '0', data->digits + 48, 'd', '\0'}, code);
	
	free(hmac);
	free(byte_string);
	free(byte_secret);
	return code;
}

/*
	Deocdes the BASE32 secret key.
	Ensures you give the proper block size of BASE32.
	Puts the result in out_str without null termination.
	Returns 0 on error, 1 on success
	
	Padding with = is good practice up to 8 byte boundaries.
	  (ex: ==123456, ===12345, =1234567)
*/
int otp_byte_secret(OTPData* data, size_t size, char* out_str) {
	if(out_str == NULL)
		return 0;
	if(size % 8 != 0)
		return 0;
	base32_decode((unsigned char*)data->base32_secret, (unsigned char*)out_str);
	return 1;
}

/*
	Basic function that converts an int into byte-char array.
	Puts the result in out_str without null termination.
	The out_str should already be null-terminated and 9 bytes long.
	The implementation requires 4 bytes of padding extra to the left, so memset out_str.
	Only one byte per char is supported.
	Returns 0 on error, 1 on success
*/
int otp_int_to_bytestring(int integer, char* out_str) {
	if(out_str == NULL)
		return 0;
	out_str[4] = integer >> 24; // I don't like this method of breaking down the bytes
	out_str[4+1] = integer >> 16;
	out_str[4+2] = integer >> 8;
	out_str[4+3] = integer;
	return 1;
}

/*
	Using a list of letters, generates a random BASE32.
	Puts the result in out_str without null termination.
	The length (len) standard is 16. If NULL, 16.
	Returns (1)true, or (0)false on failure.
	
	Google authenticator requires len to be 16. (3/4/2017)
	Ensure that srand(time(NULL)) is called before this,
	  or the random generator is seeded. This prevents
	  getting the same number first every time.
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
	Compares a user-given key with a newly generated key at a time.
	Returns (1)true, or (0)false if a key doesn't match.
	
	See totp_verify for more information.
	
	TODO: implement an expensive version to prevent mass iterations to crack
*/
int totp_compares(OTPData* data, char* key, size_t increment, unsigned int for_time) {
	char* time_str = calloc(8, sizeof(char));
	if(totp_at(data, for_time, increment, time_str) == 0) {
		free(time_str);
		return 0;
	}
	for (size_t i=0; i<8; i++) {
		if(key[i] != time_str[i]) {
			free(time_str);
			return 0;
		}
	}
	free(time_str);
	return 1;
}

int totp_comparei(OTPData* data, int key, size_t increment, unsigned int for_time) {
	char* key_str = calloc(8, sizeof(char));
	int status = totp_compares(data, key_str, increment, for_time);
	free(key_str);
	return status;
}

/*
	Generates an otp at a given time, which interval offsets.
	Puts the result in out_str without null termination.
	Returns (>1)true the otp generated,
	  or (0)false on an otp_generate failure.
	
	For example,
	  020321 is the code for the current 30 second block.
	  159121 is the code for the next 30 second block.
	  Counter offset makes it so you do not have to add
	    30 seconds to for_time, which can get messy.
	See otp_generate for more info.
*/
int totp_at(OTPData* data, unsigned int for_time, size_t counter_offset, char* out_str) {
	return otp_generate(data, totp_timecode(data, for_time) + counter_offset, out_str);
}

/*
	Generates an otp at the current time.
	Puts the result in out_str without null termination.
	Returns (>1)true the otp generated,
	  or (0)false on an otp_generate failure.
	
	See otp_generate for more info.
*/
int totp_now(OTPData* data, char* out_str) {
	return otp_generate(data, totp_timecode(data, time(NULL)), out_str);
}

/*
	Verifies if a code falls within time blocks defined by the timecode.
	See timecode for explanation on these time blocks.
	Returns (1)true, or (0) false if a key doesn't matches one of the
	  time-generated keys.
*/
int totp_verify(OTPData* data, int key, unsigned int for_time, int valid_window) {
	if(valid_window > 0) {
		for (int i=-valid_window; i<valid_window; i++) {
			const int cmp = totp_comparei(data, key, i, for_time);
			if(cmp == 1) return cmp;
		}
		return 0;
	}
	return totp_comparei(data, key, 0, for_time);
}

/*
	Generates and returns a time block int.
	
	A time block is a section where seconds don't matter. Only intervals.
	For example,
		30 second intervals
		Time is 1240512
		There are 41350.4 30 seconds
		In 30 seconds, this will be 1240513
	When verifying a key with totp, the timecode MUST be the same.
	Time blocks tell how long a key has till it is invalid. This can be
	  extended using totp_verify's valid_window int by multiples.
	  For example,
	    30 second time block
		2 valid_window
		totp_verify checks (-2,-1,0,1,2) time blocks
		  that means (-60,-30,0,30,60) seconds resprectively
		  and the code is good for 60 seconds in the future to 60 in past
		The checked time blocks are relative to the current time block
		  given in for_time int of totp_verify
		If interval was 20, +1 every
		  20 seconds (-40,-20,0,20,40)
*/
int totp_timecode(OTPData* data, unsigned int for_time) {
	return for_time/data->interval;
}



/*
	Compares a user-given key with a otp generated with a counter number.
	The user should be in sync with the counter so that keys are in sync.
	Returns (1)true, or (0)false if the two keys are dislike.
	
	It is NOT necessary to make this expensive. This can't be
	  brute forced. If an attempt was made, it would go out of
	  sync with the user. It is not like they have the current
	  counter anyways to keep trying. HOWEVER, the problem
	  of the counters becoming desynced is an issue.
*/
int hotp_comparei(OTPData* data, int key, size_t counter) {
	char* key_str = calloc(8, sizeof(char));
	char* cnt_str = calloc(8, sizeof(char));
	sprintf(key_str, "%d", key);
	hotp_at(data, counter, cnt_str);
	int i;
	for (i=0; i<8; i++) {
		if(key_str[i] != cnt_str[i]) {
			free(cnt_str);
			free(key_str);
			return 0;
		}
	}
	free(cnt_str);
	free(key_str);
	return 1;
}

int hotp_compares(OTPData* data, char* key, size_t counter) {
	char* cnt_str = calloc(8, sizeof(char));
	hotp_at(data, counter, cnt_str);
	int i;
	for (i=0; i<8; i++) {
		if(key[i] != cnt_str[i]) {
			free(cnt_str);
			return 0;
		}
	}
	free(cnt_str);
	return 1;
}

/*
	Generates an otp for the current counter.
	Puts the result in out_str without null termination.
	Returns the generated otp.
	
	See otp_generate for more info.
*/
int hotp_at(OTPData* data, size_t counter, char* out_str) {
	return otp_generate(data, counter, out_str);
}

/*
	Verifies that the key matches the counter.
	Returns (1)true, or (2) false if the two keys are like.
	
	This function is added for ease of use. It is
	  just a wrapper function to prevent code
	  complexity.
*/
int hotp_verify(OTPData* data, int key, size_t counter) {
	return hotp_comparei(data, key, counter);
}


