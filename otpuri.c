
#include "otpuri.h"

#include <stdlib.h>
#include <stdio.h>

#include <string.h>


/*
	Encodes all given data into url-safe data. Null-terminates
	  returned string. Caller must free the returned pointer.
	  Will treat embedded \0's as valid characters.
	
	length is the length in bytes of input string data
	data is the optionally null-terminated string to encode
	
	Returns
			Pointer to malloc'd url-safe data string
		error, 0
*/
char* otpuri_encode_url(const char* data, size_t length)
{
	static const char to_test[] = "\"<>#%@{}|\\^~[]` ?&";
	
	size_t cData_i = 0;
	char* cData = calloc(3*length + 1, sizeof(char));
	if (cData == 0)
		return 0;
	
	for (size_t i=0; i<length; i++)
	{
		cData[cData_i] = data[i];
		if (data[i] < 0x20 || data[i] >= 0x7F)
		{
			cData_i += snprintf(cData + cData_i, 3+1, "%%%.2X", data[i]);
			cData_i--;
		}
		else
		{
			for (size_t j=0; j<18; j++)
			{
				if (to_test[j] == data[i])
				{
					cData_i += snprintf(cData + cData_i, 3+1, "%%%.2X", data[i]);
					cData_i--;
					break;
				}
			}
		}
		cData_i++;
	}
	
	cData = realloc(cData, cData_i + 1);
	if (cData == 0)
		return 0;
	
	return cData;
}

/*
	Builds a valid, url-safe URI which is used for applications such as QR codes.
	Null-terminates returned string. Caller must free the returned pointer.
	
	issuer is the null-terminated string of company name
	name is the null-terminated string of username
	digest is the null-terminated string of HMAC encryption algorithm
	
	Returns
			Pointer to malloc'd url-safe URI string
		error, 0
		
*/
char* otpuri_build_uri(OTPData* data, const char* issuer, const char* name, const char* digest) {
	if(issuer == 0 || name == 0)
		return 0;
	
	char* cissuer = otpuri_encode_url(issuer, strlen(issuer));
	char* cname = otpuri_encode_url(name, strlen(name));
	
	char* secret = otpuri_encode_url(data->base32_secret, strlen(data->base32_secret));
	char* cdigest = otpuri_encode_url(digest, strlen(digest));
	
	char* digits = calloc(3, sizeof(char));
	
	char* time = 0;
	char* args = 0;
	
	char* uri = 0;
	
	if(cissuer == 0 || cname == 0 || secret == 0 || cdigest == 0 || digits == 0)
		goto exit;
	
	snprintf(digits, 2, "%Iu", data->digits);
	
	size_t arg_len = 9 + 9 + 12 + 9
					+ strlen(secret) + strlen(cissuer) + strlen(cdigest) + strlen(digits);
	
	const char* otp_type = 0;
	switch(data->method)
	{
		case TOTP:
			otp_type = "totp";
			time = calloc(9 + 11 + 1, sizeof(char));
			snprintf(time, 9 + 11 + 1, "%s%Iu", "&period=", data->interval);
			arg_len += strlen(time);
			break;
		case HOTP:
			otp_type = "hotp";
			time = calloc(10 + 11 + 1, sizeof(char));
			snprintf(time, 10 + 11 + 1, "%s%llu", "&counter=", data->count);
			arg_len += strlen(time);
			break;
		default:
			otp_type = "otp";
			break;
	}
	
	size_t uri_len = 13 + 4 + strlen(cissuer) + strlen(cname) + arg_len;
	
	args = calloc(arg_len + 1, sizeof(char));
	uri = calloc(uri_len + 1, sizeof(char));
	if(args == 0 || uri == 0)
		goto exit;
	
	strncat(args, "?secret=", 9);
	strcat(args, secret);
	strncat(args, "&issuer=", 9);
	strcat(args, cissuer);
	strncat(args, "&algorithm=", 12);
	strcat(args, cdigest);
	strncat(args, "&digits=", 9);
	strcat(args, digits);
	if(time != 0)
	{
		strcat(args, time);
	}
	
	snprintf(uri, uri_len * sizeof(char), "otpauth://%s/%s:%s%s", otp_type, cissuer, cname, args);
	
exit:
	free(args);
	free(time);
	free(digits);
	free(cdigest);
	free(secret);
	free(cname);
	free(cissuer);
	return uri;
}

