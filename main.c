
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "cotp.h"
#include "base32.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>


void hmac_algo(char byte_secret[], char byte_string[], char out[]) {
	
	unsigned int len = 20;
	
	HMAC(EVP_sha1(), (unsigned char*)byte_secret, 10, (unsigned char*)byte_string, 8, (unsigned char*)out, &len);
	
}

int main(int arc, char** argv) {

	//srand(time(NULL));
	char base32_secret[17] = "JBSWY3DPEHPK3PXP\0";
	//otp_random_base32(16, default_chars, base32_secret);
	
	// for OTP generation
	char digest[5] = "sha1\0";
	
	OTPData data;
	totp_init(&data, base32_secret, 160, hmac_algo, digest, 6, 30);
	
	printf("// data //\n");
	printf("Digits: %d\n", data.digits);
	printf("Interval: %d\n", data.interval);
	printf("Method: %d\n", data.method);
	
	printf("Bits: %d\n", data.bits);
	printf("Digest: %s\n", data.digest);
	printf("Secret: %s\n", data.base32_secret);
	printf("// data //\n");
	
	// char code[data.digits+1];
	// memset(code, 0, data.digits+1);
	// totp_now(&data, code);
	
	// printf("OTP Generated: %s\n", code);
	
	// char code[data.digits+1];
	// memset(code, 0, data.digits+1);
	// hotp_at(&data, 1, code);

	// printf("HOTP Code: %s\n", code);
	
	char ho1 = hotp_verify(&data, 996554, 1);
	printf("Successfull? %d\n", ho1);
	
	char bol = totp_verify(&data, 236351, time(NULL), 4);
	printf("Successfull? %d\n", bol);
	
	return 0;
}

