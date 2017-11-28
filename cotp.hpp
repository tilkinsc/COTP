
#pragma once

#if defined(__cplusplus)

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
		OTP(const char* base32_secret, size_t bits, COTP_ALGO algo, const char* digest, size_t digits) {
			data = otp_new(base32_secret, bits, algo, digest, digits);
		}
		~OTP() {
			otp_free(data);
			data = nullptr;
		}
		
		// returns data struct for serialization or something
		// discouraged to use this class and separate the struct
		OTPData* getDataStruct() {
			return data;
		}
		
		// generates an otp
		// returns the integer, outputs the string version via output var
		int generate(int input, char* output) {
			return otp_generate(data, input, output);
		}
		
		// converts the byte secret from base32 to the actual data
		int byte_secret(size_t size, char* out_str) {
			return otp_byte_secret(data, size, out_str);
		}
		
		// used internally, generates a byte string out of an 4-byte int
		// ints need to be at least 4 bytes.
		int int_to_bytestring(int integer, char* out_str) {
			return otp_int_to_bytestring(integer, out_str);
		}
		
		// generates a random base32 code
		static int random_base32(size_t len, const char* chars, char* out_str) {
			return otp_random_base32(len, chars, out_str);
		}
		
		// returns the default characters used to generate a base32 code
		static const char* getDefaultChars() {
			return otp_DEFAULT_BASE32_CHARS;
		}
		
		// shouldn't have to use this function, unless you have a global OTP/TOTP/HOTP variable
		void free() {
			otp_free(data);
			data = nullptr;
		}
		
};

class TOTP : public OTP {
	
	public:
		TOTP(const char* base32_secret, size_t bits, COTP_ALGO algo, const char* digest, size_t digits, size_t interval)
				: OTP(base32_secret, bits, algo, digest, digits) {
			data = totp_new(base32_secret, bits, algo, digest, digits, interval);
		}
		
		// generates a code at a certain timecode
		int at(unsigned int for_time, size_t counter_offset, char* out_str) {
			return totp_at(data, for_time, counter_offset, out_str);
		}
		
		// generates a code at the current time
		// before using, please srand(time(NULL)); (seed the C random generator)
		int now(char* out_str) {
			return totp_now(data, out_str);
		}
		
		// hid the function totp_compare, no practical use. Is used internally
		
		// verifys an otp for the timecode given in a valid window
		int verify(int key, unsigned int for_time, size_t valid_window) {
			return totp_verifyi(data, key, for_time, valid_window);
		}
		
		// verifys an otp for the timecode given in a valid window
		int verify(char* key, unsigned int for_time, size_t valid_window) {
			return totp_verifys(data, key, for_time, valid_window);
		}
		
		// calculates time a key has to live from a point in time
		unsigned int valid_until(unsigned int for_time, size_t valid_window) {
			return totp_valid_until(data, for_time, valid_window);
		}
		
		// generates a timecode for the given time
		int timecode(unsigned int for_time) {
			return totp_timecode(data, for_time);
		}
		
};

class HOTP : public OTP {
	
	public:
		
		HOTP(const char* base32_secret, size_t bits, COTP_ALGO algo, const char* digest, size_t digits)
				: OTP(base32_secret, bits, algo, digest, digits) {
			data = hotp_new(base32_secret, bits, algo, digest, digits);
		}
		
		// hid the function hotp_compare, no practical use. Is used internally.
		
		// generates a otp at a certain number (number of hits)
		int at(size_t counter, char* out_str) {
			return hotp_at(data, counter, out_str);
		}
		
		// verifies the key generated with the current counter server-side
		int verify(int key, size_t counter) {
			return hotp_verifyi(data, key, counter);
		}
		
		// verifies the key generated with the current counter server-side
		int verify(char* key, size_t counter) {
			return hotp_verifys(data, key, counter);
		}
	
};

#else
#	error "cotp.hpp is a C++ header. __cplusplus not defined."
#endif

