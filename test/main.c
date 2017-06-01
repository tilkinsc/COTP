
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../cotp.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>


int hmac_algo(const char byte_secret[], const char byte_string[], char out[]) {
	
	unsigned int len = 20;
	
	return HMAC(EVP_sha1(), (unsigned char*)byte_secret, 10, (unsigned char*)byte_string, 8, (unsigned char*)out, &len) == NULL ? 0 : 1;
	
}

int main(int argc, char** argv) {

	//srand(time(NULL));
	const char base32_secret[] = "JBSWY3DPEHPK3PXP";
	//otp_random_base32(16, default_chars, base32_secret);
	
	// for OTP generation
	const char digest[] = "SHA1";
	
	OTPData* data = totp_new(base32_secret, 160, hmac_algo, digest, 6, 30);
	
	// Print the stuff in OTPData
	printf("// data //\n");
	printf("Digits: %d\n", data->digits);
	printf("Interval: %d\n", data->interval);
	printf("Method: %d\n", data->method);
	
	printf("Bits: %d\n", data->bits);
	printf("Digest: %s\n", data->digest);
	printf("Secret: %s\n", data->base32_secret);
	printf("// data //\n");
	
	
	
	// Do a TOTP example
	// char code[data.digits+1];
	// memset(code, 0, data.digits+1);
	// totp_now(&data, code);
	
	// printf("OTP Generated: %s\n", code);
	
	int bol = totp_verify(data, 600223, time(NULL), 4);
	printf("Successfull? %d\n", bol);
	
	// Do a HOTP example
	// char code[data.digits+1];
	// memset(code, 0, data.digits+1);
	// hotp_at(&data, 1, code);

	// printf("HOTP Code: %s\n", code);
	
	// char ho1 = hotp_verify(&data, 996554, 1);
	// printf("Successfull? %d\n", ho1);
	
	otp_free(data);
	
	return 0;
}

