
#pragma once

#if defined(__cplusplus)

extern "C"
{
	#include "cotp.h"
	#include "otpuri.h"
}

#include <cstdint>

// see cotp.c for descriptions
class OTP
{
	protected:
		OTPData* data;
		
	public:
		OTP(OTPData* data, const char* base32_secret, COTP_ALGO algo, uint32_t digits)
		{
			this->data = otp_new(data, base32_secret, algo, digits);
		}
		
		~OTP()
		{
			data = nullptr;
		}
		
		int generate(int64_t input, char* output)
		{
			return otp_generate(data, input, output);
		}
		
		int byte_secret(char* out_str)
		{
			return otp_byte_secret(data, out_str);
		}
		
		int num_to_bytestring(uint64_t integer, char* out_str)
		{
			return otp_num_to_bytestring(integer, out_str);
		}
		
		// Caller must free the returned pointer.
		char* build_uri(const char* issuer, const char* name, const char* digest)
		{
			return otpuri_build_uri(data, issuer, name, digest);
		}
		
		OTPData* data_struct()
		{
			return data;
		}
		
		static int random_base32(size_t len, const char* chars, char* out_str)
		{
			return otp_random_base32(len, chars, out_str);
		}
		
		static const char* default_chars()
		{
			return OTP_DEFAULT_BASE32_CHARS;
		}
		
};

// see cotp.c for descriptions
class TOTP
{
	protected:
		OTPData* data;
		
	public:
		TOTP(OTPData* data, const char* base32_secret, COTP_ALGO algo, COTP_TIME time, uint32_t digits, uint32_t interval)
		{
			this->data = totp_new(data, base32_secret, algo, time, digits, interval);
		}
		
		~TOTP()
		{
			data = nullptr;
		}
		
		int at(uint64_t for_time, uint64_t offset, char* out_str)
		{
			return totp_at(data, for_time, offset, out_str);
		}
		
		int now(char* out_str)
		{
			return totp_now(data, out_str);
		}
		
		int verify(const char* key, uint64_t for_time, int64_t valid_window)
		{
			return totp_verify(data, key, for_time, valid_window);
		}
		
		uint64_t valid_until(uint64_t for_time, int64_t valid_window)
		{
			return totp_valid_until(data, for_time, valid_window);
		}
		
		uint64_t timecode(uint64_t for_time)
		{
			return totp_timecode(data, for_time);
		}
		
		// Caller must free the returned pointer.
		char* build_uri(const char* issuer, const char* name, const char* digest)
		{
			return otpuri_build_uri(data, issuer, name, digest);
		}
		
		OTPData* data_struct()
		{
			return data;
		}
		
		static int random_base32(size_t len, const char* chars, char* out_str)
		{
			return otp_random_base32(len, chars, out_str);
		}
		
		static const char* default_chars()
		{
			return OTP_DEFAULT_BASE32_CHARS;
		}
		
};

// see cotp.c for descriptions
class HOTP
{
	protected:
		OTPData* data;
		
	public:
		HOTP(OTPData* data, const char* base32_secret, COTP_ALGO algo, uint32_t digits, uint64_t count)
		{
			this->data = hotp_new(data, base32_secret, algo, digits, count);
		}
		
		~HOTP()
		{
			data = nullptr;
		}
		
		int at(uint64_t counter, char* out_str)
		{
			return hotp_at(data, counter, out_str);
		}
		
		int next(char* out_str)
		{
			return hotp_next(data, out_str);
		}
		
		int compare(const char* key, uint64_t counter)
		{
			return hotp_compare(data, key, counter);
		}
		
		// Caller must free the returned pointer.
		char* build_uri(const char* issuer, const char* name, const char* digest)
		{
			return otpuri_build_uri(data, issuer, name, digest);
		}
		
		OTPData* data_struct()
		{
			return data;
		}
		
		static int random_base32(size_t len, const char* chars, char* out_str)
		{
			return otp_random_base32(len, chars, out_str);
		}
		
		static const char* default_chars()
		{
			return OTP_DEFAULT_BASE32_CHARS;
		}
		
};

#else
#	error "cotp.hpp is a C++ header. __cplusplus not defined."
#endif

