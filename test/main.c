
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../cotp.h"
#include "../otpuri.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>


// byte_secret is unbase32 key
// byte_string is data to be HMAC'd
int hmac_algo_sha1(const char byte_secret[], const char byte_string[], char out[]) {
	
	// output len
	unsigned int len = SHA1_BYTES;
	
	// return the HMAC success
	return HMAC(
			EVP_sha1(),											// algorithm
			(unsigned char*)byte_secret, 10,	// key
			(unsigned char*)byte_string, 8,	// data
			(unsigned char*)out, &len) == 0 ? 0 : 1;			// output
}

int hmac_algo_sha256(const char byte_secret[], const char byte_string[], char out[]) {
	
	// output len
	unsigned int len = SHA256_BYTES;
	
	// return the HMAC success
	return HMAC(
			EVP_sha256(),										// algorithm
			(unsigned char*)byte_secret, strlen(byte_secret),	// key
			(unsigned char*)byte_string, strlen(byte_string),	// data
			(unsigned char*)out, &len) == 0 ? 0 : 1;			// output
}

int hmac_algo_sha512(const char byte_secret[], const char byte_string[], char out[]) {
	
	// output len
	unsigned int len = SHA512_BYTES;
	
	// return the HMAC success
	return HMAC(
			EVP_sha512(),										// algorithm
			(unsigned char*)byte_secret, strlen(byte_secret),	// key
			(unsigned char*)byte_string, strlen(byte_string),	// data
			(unsigned char*)out, &len) == 0 ? 0 : 1;			// output
}



int main(int argc, char** argv) {
	
	////////////////////////////////////////////////////////////////
	// Initialization Stuff                                       //
	////////////////////////////////////////////////////////////////
	
	const int INTERVAL	= 30;
	const int DIGITS	= 6;
	
	
	// Base32 secret to utilize
	const char BASE32_SECRET[] = "JBSWY3DPEHPK3PXP";
	
	// Seed random generator
	srand(time(NULL));
	// TODO: generate a new base32 key
	
	
	// Create OTPData struct, which decides the environment
	OTPData* tdata = totp_new(
				BASE32_SECRET,
				SHA1_BITS,
				hmac_algo_sha1,
				SHA1_DIGEST,
				DIGITS,
				INTERVAL);
	
	OTPData* hdata = hotp_new(
				BASE32_SECRET,
				SHA1_BITS,
				hmac_algo_sha1,
				SHA1_DIGEST,
				DIGITS);
	
	// Show example of URIs
	char* uri = otpuri_build_uri(tdata, "name1", "account@whatever1.com", 0);
	printf("%s\n", uri);
	free(uri);
	
	size_t counter = 52; // for example
	uri = otpuri_build_uri(hdata, "name2", "account@whatever2.com", counter);
	printf("%s\n", uri);
	free(uri);
	
	// Dump data members of struct OTPData tdata
	printf("\\\\ totp tdata \\\\\n");
	printf("tdata->digits: `%Iu`\n", tdata->digits);
	printf("tdata->interval: `%Iu`\n", tdata->interval);
	printf("tdata->bits: `%Iu`\n", tdata->bits);
	printf("tdata->method: `%u`\n", tdata->method);
	printf("tdata->algo: `0x%p`\n", tdata->algo);
	printf("tdata->digest: `%s`\n", tdata->digest);
	printf("tdata->base32_secret: `%s`\n", tdata->base32_secret);
	printf("// totp tdata //\n\n");
	
	// Dump data members of struct OTPData hdata
	printf("\\\\ hotp hdata \\\\\n");
	printf("hdata->digits: `%Iu`\n", hdata->digits);
	printf("hdata->bits: `%Iu`\n", hdata->bits);
	printf("hdata->method: `%u`\n", hdata->method);
	printf("hdata->algo: `0x%p`\n", hdata->algo);
	printf("hdata->digest: `%s`\n", hdata->digest);
	printf("hdata->base32_secret: `%s`\n", hdata->base32_secret);
	printf("// hotp hdata //\n\n");
	
	printf("Current Time: `%Iu`'\n", time(NULL));
	
	////////////////////////////////////////////////////////////////
	// BASE32 Stuff                                               //
	////////////////////////////////////////////////////////////////
	
	
	
	////////////////////////////////////////////////////////////////
	// TOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get TOTP for current time block
	//   1. Reserve memory and ensure it's null-terminated
	//   2. Generate and load totp key into tcode
	//   3. Check for error
	//   4. Free data
	char* tcode = calloc(DIGITS+1, sizeof(char));
	int totp_err_1 = totp_now(tdata, tcode);
	if(totp_err_1 == 0) {
		puts("TOTP Error 1");
		return 1;
	}
	printf("TOTP Generated: `%s`\n", tcode);
	free(tcode);
	
	
	// Do a verification for a hardcoded code
	int tv = totp_verify(tdata, 576203, time(NULL), 4);
	printf("Hardcoded Verification: `%d`\n", tv);
	
	////////////////////////////////////////////////////////////////
	// HOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get HOTP for token 1
	//   1. Reserve memory and ensure it's null-terminated
	//   2. Generated and load hotp key into hcode
	//   3. Check for error
	//   3. Free data
	char* hcode = calloc(8+1, sizeof(char));
	int hotp_err_1 = hotp_at(hdata, 1, hcode);
	if(hotp_err_1 == 0) {
		puts("HOTP Error 1");
		return 1;
	}
	printf("HOTP Generated at 1: `%s`\n", hcode);
	free(hcode);
	
	// Do a verification for a hardcoded code
	// Will succeed, 1 for JBSWY3DPEHPK3PXP == 996554
	// TODO: why did we get 915634
	char hv = hotp_verify(hdata, 996554, 1);
	printf("Hardcoded Verification: `%d`\n", hv);
	
	otp_free(hdata);
	otp_free(tdata);
	
	return 0;
}

