
#include "otpuri.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <string.h>

char* otpuri_encode_url(const char* url, size_t url_len, char* protocol) {
	static const char to_test[] = "\"<>#%{}|\\^~[]` ?&";
	
	size_t cUrl_len = url_len + 1;
	size_t cUrl_index = 0;
	char* cUrl = malloc(cUrl_len * sizeof(char));
	
	for (size_t i=0; i<url_len; i++) { // for each character
		for (size_t j=0; j<strlen(to_test); j++) { // for each matching character
			if(url[i] == to_test[j]) { // if matches, split and add encoded string
				cUrl = realloc(cUrl, (cUrl_len + 2) * sizeof(char));
				snprintf(cUrl + cUrl_index, 3, "%%%02X", url[i]);
				cUrl_len += 2;
				cUrl_index += 3;
				break;
			}
			if(j == strlen(to_test)-1)
				cUrl[cUrl_index++] = url[i];
		}
		
	}
	cUrl[url_len] = 0;
	
	return cUrl;
}

char* otpuri_build_uri(OTPData* data, char* issuer, char* name, size_t counter) {
	issuer = otpuri_encode_url(issuer, strlen(issuer), NULL);
	name = otpuri_encode_url(name, strlen(name), NULL);
	
	char* secret = otpuri_encode_url(data->base32_secret, strlen(data->base32_secret), NULL);
	char* digest = otpuri_encode_url(data->digest, strlen(data->digest), NULL);
	
	char* digits = calloc(3, sizeof(char));
	snprintf(digits, 2, "%Iu", data->digits);
	
	size_t arg_len = strlen("?secret=") + strlen("&issuer=") + strlen("&algorithm=") + strlen("&digits=")
					+ strlen(secret) + strlen(issuer) + strlen(data->digest) + strlen(digits);
	
	char* time = 0;
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
	
	
	char* args = calloc(arg_len + 1, sizeof(char));
	strncat(args, "?secret=", strlen("?secret="));
	strncat(args, secret, strlen(secret));
	strncat(args, "&issuer=", strlen("&issuer="));
	strncat(args, issuer, strlen(issuer));
	strncat(args, "&algorithm=", strlen("&algorithm="));
	strncat(args, digest, strlen(digest));
	strncat(args, "&digits=", strlen("&digits="));
	strncat(args, digits, strlen(digits));
	if(time != 0)
		strncat(args, time, strlen(time));
	args[arg_len] = '\0';
	
	
	// (base + :) + OTP/TOTP/HOTP + issuer
	size_t uri_len = 13 + 4 + strlen(issuer) + strlen(name) + arg_len;
	char* uri = malloc(uri_len + 1 * sizeof(char));
	snprintf(uri, uri_len * sizeof(char), "otpauth://%s/%s:%s%s", otp_type, issuer, name, args);
	uri[uri_len] = '\0';
	
	free(args);
	free(time);
	free(digits);
	free(digest);
	free(secret);
	free(name);
	free(issuer);
	return uri;
}

