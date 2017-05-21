
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
OTPData* otp_new(const char* base32_secret, int bits, COTP_ALGO algo, const char* digest, int digits) {
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
OTPData* totp_new(const char* base32_secret, int bits, COTP_ALGO algo, const char* digest, int digits, int interval) {
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
OTPData* hotp_new(const char* base32_secret, int bits, COTP_ALGO algo, const char* digest, int digits) {
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
	  Returns the one time password as int, aswell.
	out_str must be data->digits length + 1 (for null terminator)
	
	Returns 0 if length of data->base32_secret % 8 != 0, else code
*/
int otp_generate(OTPData* data, int input, char* out_str) {
	// get array size to unbase32 the secret string
	int secret_len = strlen(data->base32_secret);
	int desired_secret_len = UNBASE32_LEN(secret_len);
	
	// allocate memory, fill with unbase32
	char* byte_secret = calloc(desired_secret_len+1, sizeof(char));
	int bs = otp_byte_secret(data, secret_len, byte_secret);
	if(bs == 0) {
		free(byte_secret);
		return 0;
	}
	
	// allocate memory for a 4 byte int, fill with int's bytes
	char* byte_string = calloc(4+1, sizeof(char));
	otp_int_to_bytestring(input, byte_string);
	
	// convert SHA's bits into length, allocate memory, fill with decryption
	int bit_size = data->bits/8;
	char* hmac = calloc(bit_size+1, sizeof(char));
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
	
	// write temporary string to get resulting length
	char* temp_str = calloc(data->digits + 1, sizeof(char));
	sprintf(temp_str, "%d", code);
	
	// pad temp_str with 0's to ensure digit length, while moving string right to do so, to out_str
	int zeros = data->digits - strlen(out_str);
	if(zeros > 0) {
		char* zeros_str = calloc(zeros, sizeof(char));
		sprintf(out_str, "%s%s", zeros_str, temp_str);
		free(zeros_str);
	} else
		sprintf(out_str, "%s", temp_str);
	
	// null terminate
	out_str[data->digits] = '\0';
	
	free(temp_str);
	free(hmac);
	free(byte_string);
	free(byte_secret);
	return code;
}

/*
	Deocdes the BASE32 secret key.
	
	Ensures you give the proper block size of BASE32.
	Padding with = is good practice up to 8 byte boundaries.
	  (ex: ==123456, ===12345, =1234567)
	Puts the result in out_str without null termination.
	
	Returns 0 on error, 1 on success
*/
int otp_byte_secret(OTPData* data, int size, char* out_str) {
	if(size % 8 != 0) {
		printf("size mismatch.");
		return 0;
	}
	base32_decode((unsigned char*)data->base32_secret, (unsigned char*)out_str);
	return 1;
}

/*
	Basic function that converts an int into byte char array.
	Puts the result in out_str without null termination.
	
	The out_str should be 9 long, where the 8 are memset to 0.
	The 9 is '\0'. The implementation requires 4 bytes of padding extra.
	Only use can use ascii (0-255).
*/
void otp_int_to_bytestring(int integer, char* out_str) {
	out_str[4] = integer >> 24;
	out_str[4+1] = integer >> 16;
	out_str[4+2] = integer >> 8;
	out_str[4+3] = integer;
}

/*
	The length (len) standard is 16. If NULL, 16.
	Google authenticator requires it to be 16. (3/4/2017)
	Using a list of letters, generates a BASE32.
	Ensure that srand(time(NULL)) is called before this.
	Puts the result in out_str without null termination.
*/
void otp_random_base32(int len, const char* chars, char* out_str) {
	len = len > 0 ? len : 16;
	int i;
	for (i=0; i<len; i++)
		out_str[i] = chars[rand()%32];
}



/*
	Compares a user-given key with a newly generated key at a time.
	Returns (1) true, (0) false if a key matches.
	See totp_verify.
	
	Returns 0 on fail.
	
	TODO: implement an expensive version to prevent mass iterations to crack
*/
int totp_compare(OTPData* data, int key, int increment, int for_time) {
	char* key_str = calloc(8, sizeof(char));
	char* time_str = calloc(8, sizeof(char));
	sprintf(key_str, "%d", key);
	if(totp_at(data, for_time, increment, time_str) == 0) {
		free(time_str);
		free(key_str);
		return 0;
	}
	int i;
	for (i=0; i<8; i++) {
		if(key_str[i] != time_str[i]) {
			free(time_str);
			free(key_str);
			return 0;
		}
	}
	free(time_str);
	free(key_str);
	return 1;
}

/*
	Generates an otp at a given time, which interval offsets.
	For example,
	  20321 is the code for a 30 second block.
	  159121 is the code for the next 30 second block.
	  Counter offset makes it so you do not have to add
	    30 seconds to for_time.
	Returns the otp generated as int.
	See otp_generate for more info.
	Puts the result in out_str without null termination.
	
	Returns 0 on fail.
*/
int totp_at(OTPData* data, int for_time, int counter_offset, char* out_str) {
	return otp_generate(data, totp_timecode(data, for_time) + counter_offset, out_str);
}

/*
	Generates an otp at the current time.
	Returns the otp generated as int.
	See otp_generate for more info.
	Puts the result in out_str without null termination.
	
	Returns 0 on fail.
*/
int totp_now(OTPData* data, char* out_str) {
	return otp_generate(data, totp_timecode(data, time(NULL)), out_str);
}

/*
	Verifies if a code falls within blocks defined by using timecode.
	See timecode for explanation on these time blocks.
	Returns a (1)true, or (0)false number if a key matches one of the
	  time-generated keys.
*/
int totp_verify(OTPData* data, int key, int for_time, int valid_window) {
	valid_window = valid_window < 0 ? 0 : valid_window;
	for_time = for_time <= 0 ? time(NULL) : for_time;
	
	if(valid_window > 0) {
		int i;
		for (i=-valid_window; i<valid_window; i++) {
			const int cmp = totp_compare(data, key, i, for_time);
			if(cmp == 1) return cmp; // else continue
		}
		return 0;
	}
	return totp_compare(data, key, 0, for_time);
}

/*
	Generates and returns a time block int.
	A time block is a section where seconds don't matter. Only intervals.
	For example,
		30 second intervals
		Time is 1240512
		There are 41350.4 30 seconds
	When verifying a key with totp, the timecode MUST be the same.
	Time blocks tell how long a key has to live. This can be extended
	  using totp_verify's valid_window int by multiples.
	  For example,
	    30 second intervals
		totp_verify checks 5 (-2,-1,0,1,2) time blocks
		The checked time blocks are relative to the base block
		  given in for_time int of totp_verify
*/
int totp_timecode(OTPData* data, int for_time) {
	return for_time/data->interval;
}



/*
	Compares a user-given key with a otp generated with a counter number.
	The user should be in sync with the counter so that keys are in sync.
	Returns (1)true, or (0)false if the two keys are like.
	
	It is NOT necessary to make this expensive. This can't be
	  brute forced. If an attempt was made, it would go out of
	  sync with the user. It is not like they have the current
	  counter anyways to keep trying. HOWEVER, the problem
	  of the counters becoming desynced is an issue.
*/
int hotp_compare(OTPData* data, int key, int counter) {
	char* key_str = calloc(8, sizeof(char));
	char* cnt_str = calloc(8, sizeof(char));
	sprintf(key_str, "%d", key);
	hotp_at(data, counter, cnt_str);
	int i;
	for (i=0; i<8; i++) {
		printf("|%c| cmp |%c|\n", key_str[i], cnt_str[i]);
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

/*
	Generates an otp for the current counter.
	Returns the generated otp.
	See otp_generate for more info.
	Puts the result in out_str without null termination.
*/
int hotp_at(OTPData* data, int counter, char* out_str) {
	return otp_generate(data, counter, out_str);
}

/*
	Verifies that the key matches the counter.
	This function is added for ease of use. It is
	  just a wrapper function to prevent code
	  complexity.
	Returns (1)true, or (2) false if the two keys are like.
*/
int hotp_verify(OTPData* data, int key, int counter) {
	return hotp_compare(data, key, counter);
}


