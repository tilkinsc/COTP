
#pragma once

extern "C" {
	#include "cotp.h"
}

// almost all functions have a form of error they can return
// please check accordingly, and look at cotp.c for information
// about the various errors. Rule of thumb: If return 0, you have
// an error.
class OTP {
	
	// data structure should be untouched. It is managed by functions.
	// don't forget to clean it up using free() if it is global and unneeded,
	// or let the deconstructor do its job out of scope
	protected:
		OTPData* data;
		
	public:
		OTP(const char* base32_secret, int bits, COTP_ALGO algo, const char* digest, int digits) {
			data = otp_new(base32_secret, bits, algo, digest, digits);
		}
		~OTP() {
			otp_free(data);
			data = nullptr;
		}
		
		// generates an otp
		// returns the integer, outputs the string version via output var
		int generate(int input, char* output) {
			return otp_generate(data, input, output);
		}
		
		// converts the byte secret from base32 to the actual data
		int byte_secret(int size, char* out_str) {
			return otp_byte_secret(data, size, out_str);
		}
		
		// used internally, generates a byte string out of an 4-byte int
		// ints need to be at least 4 bytes.
		int int_to_bytestring(int integer, char* out_str) {
			otp_int_to_bytestring(integer, out_str);
		}
		
		// generates a random base32 code
		int random_base32(int len, const char* chars, char* out_str) {
			otp_random_base32(len, chars, out_str);
		}
		
		// returns the default characters used to generate a base32 code
		const char* getDefaultChars() {
			return otp_DEFAULT_CHARS;
		}
		
		// shouldn't have to use this function, unless you have a global OTP/TOTP/HOTP variable
		void free() {
			otp_free(data);
			data = nullptr;
		}
		
};

class TOTP : public OTP {
	
	public:
		TOTP(const char* base32_secret, int bits, COTP_ALGO algo, const char* digest, int digits, int interval)
				: OTP(base32_secret, bits, algo, digest, digits) {
			data = totp_new(base32_secret, bits, algo, digest, digits, interval);
		}
		
		// generates a code at a certain timecode
		int at(int for_time, int counter_offset, char* out_str) {
			return totp_at(data, for_time, counter_offset, out_str);
		}
		
		// generates a code at the current time
		// before using, please srand(time(NULL)); (seed the C random generator)
		int now(char* out_str) {
			return totp_now(data, out_str);
		}
		
		// hid the function totp_compare, no practical use. Is used internally.
		
		// verifys an otp for the timecode given in a valid window
		int verify(int key, int for_time, int valid_window) {
			return totp_verify(data, key, for_time, valid_window);
		}
		
		// generates a timecode for the given time
		int timecode(int for_time) {
			return totp_timecode(data, for_time);
		}
		
};

class HOTP : public OTP {
	
	public:
		
		HOTP(const char* base32_secret, int bits, COTP_ALGO algo, const char* digest, int digits)
				: OTP(base32_secret, bits, algo, digest, digits) {
			data = hotp_new(base32_secret, bits, algo, digest, digits);
		}
		
		// hid the function hotp_compare, no practical use. Is used internally.
		
		// generates a otp at a certain number (number of hits)
		int at(int counter, char* out_str) {
			return hotp_at(data, counter, out_str);
		}
		
		// verifies the key generated with the current counter server-side
		int verify(int key, int counter) {
			return hotp_verify(data, key, counter);
		}
	
};

