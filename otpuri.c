
#include "otpuri.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>


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
COTPRESULT otpuri_encode_url(const char* data, size_t length, char* output)
{
	if (data == NULL || output == NULL)
		return OTP_ERROR;
	
	static const char to_test[] = "\"<>#%@{}|\\^~[]` ?&";
	
	size_t output_i = 0;
	for (size_t i=0; i<length; i++)
	{
		output[output_i] = data[i];
		if (data[i] < 0x20 || data[i] >= 0x7F)
		{
			output_i += snprintf(output + output_i, 3+1, "%%%.2X", data[i]);
			output_i--;
		}
		else
		{
			for (size_t j=0; j<18; j++)
			{
				if (to_test[j] == data[i])
				{
					output_i += snprintf(output + output_i, 3+1, "%%%.2X", data[i]);
					output_i--;
					break;
				}
			}
		}
		output_i++;
	}
	
	return OTP_OK;
}

/*
	Returns the maximum expected length of an array needed to fill a buffer
	  with an otpuri not including the null-termination.
	
	Returns
			Length in bytes of an array to match an otpuri generation
*/
size_t otpuri_strlen(OTPData* data, const char* issuer, const char* name, const char* digest)
{
	return strlen(issuer) * 2 * 3
			+ strlen(name) * 3
			+ strlen(data->base32_secret) * 3
			+ strlen(digest) * 3
			+ 100;
}

/*
	Builds a valid, url-safe URI which is used for applications such as QR codes.
	
	issuer is the null-terminated string of the company name
	name is the null-terminated string of the username
	digest is the null-terminated string of the HMAC encryption algorithm
	output is the zero'd destination the function writes the URI to
	
	Returns
			1 on success
		error, 0
		
*/
COTPRESULT otpuri_build_uri(OTPData* data, const char* issuer, const char* name, const char* digest, char* output)
{
	if (issuer == NULL || name == NULL || digest == NULL || output == NULL)
		return OTP_ERROR;
	
	strcat(output, "otpuri://");
	switch(data->method)
	{
		case TOTP:
			strcat(output, "totp");
			break;
		case HOTP:
			strcat(output, "hotp");
			break;
		default:
			strcat(output, "otp");
			break;
	}
	
	strcat(output, "/");
	
	char cissuer[strlen(issuer)*3 + 1];
	memset(cissuer, 0, strlen(issuer)*3 + 1);
	otpuri_encode_url(issuer, strlen(issuer), cissuer);
	strcat(output, cissuer);
	
	strcat(output, ":");
	
	char cname[strlen(name)*3 + 1];
	memset(cname, 0, strlen(name)*3 + 1);
	otpuri_encode_url(name, strlen(name), cname);
	strcat(output, cname);
	
	strcat(output, "?secret=");
	char csecret[strlen(data->base32_secret)*3 + 1];
	memset(csecret, 0, strlen(data->base32_secret)*3 + 1);
	otpuri_encode_url(data->base32_secret, strlen(data->base32_secret), csecret);
	strcat(output, csecret);
	
	strcat(output, "&issuer=");
	strcat(output, cissuer);
	
	strcat(output, "&algorithm=");
	char cdigest[strlen(digest)*3 + 1];
	memset(cdigest, 0, strlen(digest)*3 + 1);
	otpuri_encode_url(digest, strlen(digest), cdigest);
	strcat(output, cdigest);
	
	strcat(output, "&digits=");
	char cdigits[21];
	memset(cdigits, 0, 21);
	snprintf(cdigits, 21, "%" PRIu32, data->digits);
	strcat(output, cdigits);
	
	switch(data->method)
	{
		case TOTP:
			strcat(output, "&period=");
			char cperiod[21];
			memset(cperiod, 0, 21);
			snprintf(cperiod, 21, "%" PRIu32, data->interval);
			strcat(output, cperiod);
			break;
		case HOTP:
			strcat(output, "&counter=");
			char ccounter[21];
			memset(ccounter, 0, 21);
			snprintf(ccounter, 21, "%" PRIu64, data->count);
			strcat(output, ccounter);
			break;
		default:
			break;
	}
	
	return OTP_OK;
}

