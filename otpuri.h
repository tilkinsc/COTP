#pragma once

#include "cotp.h"

size_t otpuri_strlen(OTPData* data, const char* issuer, const char* name, const char* digest);
COTPRESULT otpuri_encode_url(const char* data, size_t length, char* output);
COTPRESULT otpuri_build_uri(OTPData* data, const char* issuer, const char* name, const char* digest, char* output);
