#pragma once

#include "cotp.h"

char* otpuri_encode_url(const char* data, size_t data_len);
char* otpuri_build_uri(OTPData* data, const char* issuer, const char* name, const char* digest);

