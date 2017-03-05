
#include "cotp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "base32.h"



/*
	Default characters used in BASE32 digests.
	For use with otp_random_base32()
*/
const char default_chars[32] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5',
	'6', '7'
};



/*
	Functions to initialize the data struct OTPData.
	Everything is set but the interval in only the occasion you
	  aren't using TOTP.
	Providing the HMAC algorithm is necessary.
	Google authenticator, as of 3/4/2017, only supports SHA1+HMAC.
	You can use anything though, but must require some form to attain
	  a code, like google authenticator. Also works with authy.
*/
void otp_init(OTPData* data, char base32_secret[], int bits, void (*ALGORITHM)(char[], char[], char[]), char digest[], int digits) {
	data->digits = digits ? digits : 6;
	
	data->base32_secret = &base32_secret[0];
	data->digest = &digest[0];
	data->ALGORITHM = ALGORITHM;
	data->bits = bits;
	
	data->method = OTP;
}

void totp_init(OTPData* data, char base32_secret[], int bits, void (*ALGORITHM)(char[], char[], char[]), char digest[], int digits, int interval) {
	otp_init(data, base32_secret, bits, ALGORITHM, digest, digits);
	data->method = TOTP;
	data->interval = interval;
}

void hotp_init(OTPData* data, char base32_secret[], int bits, void (*ALGORITHM)(char[], char[], char[]), char digest[], int digits) {
	otp_init(data, base32_secret,  bits, ALGORITHM, digest, digits);
	data->method = HOTP;
}



/*
	Generates a one time password integer as non-'\0' char array.
	  Returns the one time password as int, aswell.
	You must memset out_str.
*/
int otp_generate(OTPData* data, int input, char out_str[]) {
	int secret_len = strlen(data->base32_secret);
	int desired_secret_len = UNBASE32_LEN(secret_len);
	char byte_secret[desired_secret_len+1];
	memset(byte_secret, 0, desired_secret_len+1);
	otp_byte_secret(data, secret_len, byte_secret);
	
	char byte_string[4+1];
	memset(byte_string, 0, 5);
	otp_int_to_bytestring(input, byte_string);
	
	int bit_size = data->bits/8;
	char hmac[bit_size+1];
	memset(hmac, 0, bit_size+1);
	(*(data->ALGORITHM))(byte_secret, byte_string, hmac);
	
	int offset = (hmac[bit_size-1] & 0xF);
	
	int code =
		(hmac[offset] & 0x7F) << 24 |
		(hmac[offset+1] & 0xFF) << 16 |
		(hmac[offset+2] & 0xFF) << 8 |
		(hmac[offset+3] & 0xFF);
	code %= (int)pow(10, data->digits);
	
	sprintf(out_str, "%d", code);
	
	int zeros = data->digits - strlen(out_str);
	if(zeros != 0) {
		int i;
		for (i=data->digits-1; i>=0; i--)
			out_str[i] = out_str[i-zeros];
		for (i=0; i<zeros; i++)
			out_str[i] = '0';
	}
	return code;
}

/*
	Deocdes the BASE32 secret key.
	Ensures you give the proper block size of BASE32.
	Padding with = is good practice up to 8 byte boundaries.
	Puts the result in out_str without null termination.
*/
void otp_byte_secret(OTPData* data, int size, char out_str[]) {
	if(size % 8 != 0) {
		printf("size mismatch.");
		return;
	}
	base32_decode((unsigned char*)data->base32_secret, (unsigned char*)out_str);
}

/*
	Basic function that converts an int into byte array.
	Puts the result in out_str without null termination.
	
	The out_str should be 9 long, where the 8 are memset to 0.
	The 9 is '\0'. The implementation requires 4 bytes of padding extra.
	Only use ascii (0-255).
*/
void otp_int_to_bytestring(int integer, char out_str[]) {
	int j = 4;
	out_str[j] = integer >> 24;
	out_str[j+1] = integer >> 16;
	out_str[j+2] = integer >> 8;
	out_str[j+3] = integer;
}

/*
	The length (len) standard is 16. If NULL, 16.
	Using a list of letters, generates a BASE32.
	Ensure that srand(time(NULL)) is called before this.
	Puts the result in out_str without null termination.
*/
void otp_random_base32(int len, const char chars[], char out_str[]) {
	len = len > 0 ? len : 16;
	int i;
	for (i=0; i<len; i++)
		out_str[i] = chars[rand()%32];
}



/*
	Compares a user-given key with a newly generated key at a time.
	Returns (1) true, (0) false if a key matches.
	See totp_verify.
	
	TODO: implement an expensive version to prevent mass iterations to crack
*/
char totp_compare(OTPData* data, int key, int increment, int for_time) {
	char key_str[8];
	char time_str[8];
	memset(key_str, 0, 8);
	memset(time_str, 0, 8);
	sprintf(key_str, "%d", key);
	totp_at(data, for_time, increment, time_str);
	int i;
	for (i=0; i<8; i++) {
		if(key_str[i] != time_str[i])
			return 0;
	}
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
*/
int totp_at(OTPData* data, int for_time, int counter_offset, char out_str[]) {
	return otp_generate(data, totp_timecode(data, for_time) + counter_offset, out_str);
}

/*
	Generates an otp at the current time.
	Returns the otp generated as int.
	See otp_generate for more info.
	Puts the result in out_str without null termination.
*/
int totp_now(OTPData* data, char out_str[]) {
	return otp_generate(data, totp_timecode(data, time(NULL)), out_str);
}

/*
	Verifies if a code falls within blocks defined by using timecode.
	See timecode for explanation on these time blocks.
	Returns a (1)true, or (0)false number if a key matches one of the
	  time-generated keys.
*/
char totp_verify(OTPData* data, int key, int for_time, int valid_window) {
	valid_window = valid_window < 0 ? 0 : valid_window;
	for_time = for_time <= 0 ? time(NULL) : for_time;
	
	if(valid_window > 0) {
		int i;
		for (i=-valid_window; i<valid_window; i++) {
			char cmp = totp_compare(data, key, i, for_time);
			if(cmp) return cmp; // else continue
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
char hotp_compare(OTPData* data, int key, int counter) {
	char key_str[8];
	char cnt_str[8];
	memset(key_str, 0, 8);
	memset(cnt_str, 0, 8);
	sprintf(key_str, "%d", key);
	hotp_at(data, counter, cnt_str);
	int i;
	for (i=0; i<8; i++) {
		printf("|%c| cmp |%c|\n", key_str[i], cnt_str[i]);
		if(key_str[i] != cnt_str[i])
			return 0;
	}
	return 1;
}

/*
	Generates an otp for the current counter.
	Returns the generated otp.
	See otp_generate for more info.
	Puts the result in out_str without null termination.
*/
int hotp_at(OTPData* data, int counter, char out_str[]) {
	return otp_generate(data, counter, out_str);
}

/*
	Verifies that the key matches the counter.
	This function is added for ease of use. It is
	  just a wrapper function to prevent code
	  complexity.
	Returns (1)true, or (2) false if the two keys are like.
*/
char hotp_verify(OTPData* data, int key, int counter) {
	return hotp_compare(data, key, counter);
}


