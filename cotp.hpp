#ifndef __COTP_HPP_
#define __COTP_HPP_

extern "C" {
	#include "cotp.h"
}

class OTP {
	
	protected:
		OTPData data;
		
	public:
		OTP(const char base32_secret[], int bits, void (*ALGORITHM)(const char[], const char[], char[]), const char digest[], int digits) {
			otp_init(&data, base32_secret, bits, ALGORITHM, digest, digits);
		}
		
		int generate(int input, char output[]) {
			return otp_generate(&data, input, output);
		}
		void byte_secret(int size, char out_str[]) {
			otp_byte_secret(&data, size, out_str);
		}
		void int_to_bytestring(int integer, char out_str[]) {
			otp_int_to_bytestring(integer, out_str);
		}
		void random_base32(int len, const char chars[], char out_str[]) {
			otp_random_base32(len, chars, out_str);
		}
		
		const char* getDefaultChars() {
			return otp_DEFAULT_CHARS;
		}
		
};

class TOTP : public OTP {
	
	public:
		TOTP(const char base32_secret[], int bits, void (*ALGORITHM)(const char[], const char[], char[]), const char digest[], int digits, int interval)
				: OTP(base32_secret, bits, ALGORITHM, digest, digits) {
			totp_init(&data, base32_secret, bits, ALGORITHM, digest, digits, interval);
		}
		
		int at(int for_time, int counter_offset, char out_str[]) {
			return totp_at(&data, for_time, counter_offset, out_str);
		}
		
		int now(char out_str[]) {
			return totp_now(&data, out_str);
		}
		
		char verify(int key, int for_time, int valid_window) {
			return totp_verify(&data, key, for_time, valid_window);
		}
		
		int timecode(int for_time) {
			return totp_timecode(&data, for_time);
		}
		
	
};

class HOTP : public OTP {
	
	public:
		
		HOTP(const char base32_secret[], int bits, void (*ALGORITHM)(const char[], const char[], char[]), const char digest[], int digits)
				: OTP(base32_secret, bits, ALGORITHM, digest, digits) {
			hotp_init(&data, base32_secret, bits, ALGORITHM, digest, digits);
		}
		
		int at(int counter, char out_str[]) {
			return hotp_at(&data, counter, out_str);
		}
		
		char verify(int key, int counter) {
			return hotp_verify(&data, key, counter);
		}
	
};

#endif
