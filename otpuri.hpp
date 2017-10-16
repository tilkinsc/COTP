
#pragma once

#if defined(__cplusplus)

extern "C" {
	#include "cotp.h"
	#include "otpuri.h"
}

class OTPURI {
	
	public:
		
		static inline char* encode_url(const char* url, size_t url_len, char* protocol) {
			return otpuri_encode_url(url, url_len, protocol);
		}
		
		static inline char* build_uri(OTPData* data, char* issuer, char* name, size_t counter) {
			return otpuri_build_uri(data, issuer, name, counter);
		}
	
	
};

#else
#	error "otpuri.hpp is a C++ header. __cplusplus not defined."
#endif

