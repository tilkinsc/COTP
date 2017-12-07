
#include "otpuri.h"

#include <stdlib.h>
#include <stdio.h>

#include <string.h>


/*
	Encodes given data into url-safe data. Do use a url,
	as it will also transpose the characters that are safe/expected.
	Null-terminates returned string.
	
	Returns
			Pointer to malloc'd url-safe data string
		Out of memory, 0
*/
char* otpuri_encode_url(const char* data, size_t data_len) {
	static const char to_test[] = "\"<>#%@{}|\\^~[]` ?&";
	
	size_t cData_len = data_len + 1;
	size_t cData_index = 0;
	char* cData = malloc(cData_len * sizeof(char));
	if(cData == 0)
		return 0;
	
	for (size_t i=0; i<data_len; i++) {
		for (size_t j=0; j<strlen(to_test); j++) {
			if(data[i] == to_test[j]) {
				cData = realloc(cData, (cData_len + 2) * sizeof(char));
				if(cData == 0)
					return 0;
				snprintf(cData + cData_index, 3, "%%%02X", data[i]);
				cData_len += 2;
				cData_index += 3;
				break;
			}
			if(j == strlen(to_test)-1)
				cData[cData_index++] = data[i];
		}
		
	}
	cData[cData_len - 1] = 0;
	
	return cData;
}

/*
	Builds a valid, url-safe URI which is used for applications such as QR codes.
	Null-terminates returned string.
	
	Returns
			url-safe URI data string
		issuer or name == 0, 0
		Out of memory, 0
		
*/
char* otpuri_build_uri(OTPData* data, char* issuer, char* name, size_t counter) {
	if(issuer == 0 || name == 0)
		return 0;
	char* cissuer = otpuri_encode_url(issuer, strlen(issuer));
	char* cname = otpuri_encode_url(name, strlen(name));
	
	char* secret = otpuri_encode_url(data->base32_secret, strlen(data->base32_secret));
	char* digest = otpuri_encode_url(data->digest, strlen(data->digest));
	
	char* digits = calloc(3, sizeof(char));
	
	char* time = 0;
	char* args = 0;
	
	char* uri = 0;
	
	if(cissuer == 0 || cname == 0 || secret == 0 || digest == 0 || digits == 0)
		goto exit;
	
	snprintf(digits, 2, "%Iu", data->digits);
	
	size_t arg_len = strlen("?secret=") + strlen("&issuer=") + strlen("&algorithm=") + strlen("&digits=")
					+ strlen(secret) + strlen(cissuer) + strlen(data->digest) + strlen(digits);
	
	const char* otp_type = 0;
	switch(data->method) {
		case TOTP:
			otp_type = TOTP_CHARS;
			time = calloc(strlen("&period=") + 11 + 1, sizeof(char));
			snprintf(time, strlen("&period=") + 11 + 1, "%s%Iu", "&period=", data->interval);
			arg_len += strlen(time);
			break;
		case HOTP:
			otp_type = HOTP_CHARS;
			time = calloc(strlen("&counter=") + 11 + 1, sizeof(char));
			snprintf(time, strlen("&counter=") + 11 + 1, "%s%Iu", "&counter=", counter);
			arg_len += strlen(time);
			break;
		default:
			otp_type = OTP_CHARS;
			break;
	}
	
	// I have no clue what this means, it seems redundant
	// if(otp_type != OTP_CHARS && time == 0)
		// goto exit;
	
	// base_fmt + OTP/TOTP/HOTP + cissuer + cname + args
	size_t uri_len = 13 + 4 + strlen(cissuer) + strlen(cname) + arg_len;
	
	args = calloc(arg_len + 1, sizeof(char));
	uri = calloc(uri_len + 1, sizeof(char));
	if(args == 0 || uri == 0)
		goto exit;
	
	strncat(args, "?secret=", strlen("?secret="));
	strncat(args, secret, strlen(secret));
	strncat(args, "&issuer=", strlen("&issuer="));
	strncat(args, cissuer, strlen(cissuer));
	strncat(args, "&algorithm=", strlen("&algorithm="));
	strncat(args, digest, strlen(digest));
	strncat(args, "&digits=", strlen("&digits="));
	strncat(args, digits, strlen(digits));
	if(time != 0)
		strncat(args, time, strlen(time));
	
	snprintf(uri, uri_len * sizeof(char), "otpauth://%s/%s:%s%s", otp_type, cissuer, cname, args);
	
exit:
	free(args);
	free(time);
	free(digits);
	free(digest);
	free(secret);
	free(cname);
	free(cissuer);
	return uri;
}

