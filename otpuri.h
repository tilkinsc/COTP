
#pragma once

#include "cotp.h"

/*
	String URL Functions
*/
char* otpuri_encode_url(const char* data, size_t data_len);
char* otpuri_build_uri(OTPData* data, char* issuer, char* name, size_t counter);
