
#pragma once

#if defined(__cplusplus)

extern "C"
{
	#include "cotp.h"
	#include "otpuri.h"
}

#include <cstdint>

namespace COTP
{
	
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
			
			COTPRESULT generate(int64_t input, char* output)
			{
				return otp_generate(data, input, output);
			}
			
			COTPRESULT byte_secret(char* out_str)
			{
				return otp_byte_secret(data, out_str);
			}
			
			size_t uri_strlen(const char* issuer, const char* name, const char* digest)
			{
				return otpuri_strlen(data, issuer, name, digest);
			}
			
			COTPRESULT build_uri(const char* issuer, const char* name, const char* digest, char* output)
			{
				return otpuri_build_uri(data, issuer, name, digest, output);
			}
			
			OTPData* data_struct()
			{
				return data;
			}
			
			static COTPRESULT num_to_bytestring(uint64_t integer, char* out_str)
			{
				return otp_num_to_bytestring(integer, out_str);
			}
			
			static COTPRESULT random_base32(size_t len, char* out_str)
			{
				return otp_random_base32(len, out_str);
			}
			
	};

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
			
			COTPRESULT at(uint64_t for_time, uint64_t offset, char* out_str)
			{
				return totp_at(data, for_time, offset, out_str);
			}
			
			COTPRESULT now(char* out_str)
			{
				return totp_now(data, out_str);
			}
			
			COTPRESULT verify(const char* key, uint64_t for_time, int64_t valid_window)
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
			
			size_t uri_strlen(const char* issuer, const char* name, const char* digest)
			{
				return otpuri_strlen(data, issuer, name, digest);
			}
			
			COTPRESULT build_uri(const char* issuer, const char* name, const char* digest, char* output)
			{
				return otpuri_build_uri(data, issuer, name, digest, output);
			}
			
			OTPData* data_struct()
			{
				return data;
			}
			
			static COTPRESULT random_base32(size_t len, char* out_str)
			{
				return otp_random_base32(len, out_str);
			}
			
	};

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
			
			COTPRESULT at(uint64_t counter, char* out_str)
			{
				return hotp_at(data, counter, out_str);
			}
			
			COTPRESULT next(char* out_str)
			{
				return hotp_next(data, out_str);
			}
			
			COTPRESULT compare(const char* key, uint64_t counter)
			{
				return hotp_compare(data, key, counter);
			}
			
			size_t uri_strlen(const char* issuer, const char* name, const char* digest)
			{
				return otpuri_strlen(data, issuer, name, digest);
			}
			
			COTPRESULT build_uri(const char* issuer, const char* name, const char* digest, char* output)
			{
				return otpuri_build_uri(data, issuer, name, digest, output);
			}
			
			OTPData* data_struct()
			{
				return data;
			}
			
			static COTPRESULT random_base32(size_t len, char* out_str)
			{
				return otp_random_base32(len, out_str);
			}
			
	};
	
} // namespace COTP

#else
#	error "cotp.hpp is a C++ header. __cplusplus not defined."
#endif

