
#pragma once

#include "cotp.h"

/*
	String URL Functions
*/
char* otpuri_encode_url(const char* url, size_t url_len, char* protocol);
char* otpuri_build_uri(OTPData* data, char* issuer, char* name, size_t counter);
