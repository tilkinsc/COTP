
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#	include <sysinfoapi.h>
#elif defined(__linux__)
#	include <sys/time.h>
#else
#	error "OS not supported."
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "../cotp.h"
#include "../otpuri.h"


static const int32_t SHA1_BYTES   = 160 / 8;	// 20
static const int32_t SHA256_BYTES = 256 / 8;	// 32
static const int32_t SHA512_BYTES = 512 / 8;	// 64


// byte_secret is unbase32 key
// byte_string is data to be HMAC'd
// returns 0 for failure otherwise the length of the string
int hmac_algo_sha1(const char* byte_secret, const char* byte_string, char* out)
{
	// Output len
	unsigned int len = SHA1_BYTES;
	
	unsigned char* result = HMAC(
		EVP_sha1(),							// algorithm
		(unsigned char*)byte_secret, 10,	// key
		(unsigned char*)byte_string, 8,		// data
		(unsigned char*)out,				// output
		&len								// output length
	);
	
	// Return the HMAC success
	return result == 0 ? 0 : len;
}

int hmac_algo_sha256(const char* byte_secret, const char* byte_string, char* out)
{
	// Output len
	unsigned int len = SHA256_BYTES;
	
	unsigned char* result = HMAC(
		EVP_sha256(),						// algorithm
		(unsigned char*)byte_secret, 10,	// key
		(unsigned char*)byte_string, 8,		// data
		(unsigned char*)out,				// output
		&len								// output length
	);
	
	// Return the HMAC success
	return result == 0 ? 0 : len;
}

int hmac_algo_sha512(const char* byte_secret, const char* byte_string, char* out)
{
	// Output len
	unsigned int len = SHA512_BYTES;
	
	unsigned char* result = HMAC(
		EVP_sha512(),						// algorithm
		(unsigned char*)byte_secret, 10,	// key
		(unsigned char*)byte_string, 8,		// data
		(unsigned char*)out,				// output
		&len								// output length
	);
	
	// Return the HMAC success
	return result == 0 ? 0 : len;
}

// TODO: use a secure random generator
uint64_t get_current_time()
{
	uint64_t milliseconds = 0;
	
#if defined(_WIN32)
	FILETIME fileTime;
	GetSystemTimeAsFileTime(&fileTime);
	
	ULARGE_INTEGER largeInteger;
	largeInteger.LowPart = fileTime.dwLowDateTime;
	largeInteger.HighPart = fileTime.dwHighDateTime;
	
	milliseconds = (largeInteger.QuadPart - 116444736000000000ULL) / 10000;
#elif defined(__linux__)
	struct timeval sys_time;
	gettimeofday(&sys_time, NULL);
	
	milliseconds = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
#endif
	
	return milliseconds;
}



int main(int argc, char** argv)
{
	////////////////////////////////////////////////////////////////
	// Initialization Stuff                                       //
	////////////////////////////////////////////////////////////////
	
	const int INTERVAL	= 30;
	const int DIGITS	= 6;
	
	
	// Base32 secret to utilize
	const char BASE32_SECRET[] = "JBSWY3DPEHPK3PXP";
	
	OTPData odata1;
	memset(&odata1, 0, sizeof(OTPData));
	
	OTPData odata2;
	memset(&odata2, 0, sizeof(OTPData));
	
	// Create OTPData struct, which decides the environment
	OTPData* tdata = totp_new(
		&odata1,
		BASE32_SECRET,
		hmac_algo_sha1,
		get_current_time,
		DIGITS,
		INTERVAL
	);
	
	OTPData* hdata = hotp_new(
		&odata2,
		BASE32_SECRET,
		hmac_algo_sha1,
		DIGITS,
		0
	);
	
	// Dump data members of struct OTPData tdata
	printf("\\\\ totp tdata \\\\\n");
	printf("tdata->digits: `%u`\n", tdata->digits);
	printf("tdata->interval: `%u`\n", tdata->interval);
	printf("tdata->method: `%u`\n", tdata->method);
	printf("tdata->algo: `0x%p`\n", tdata->algo);
	printf("tdata->time: `0x%p`\n", tdata->time);
	printf("tdata->base32_secret: `%s`\n", tdata->base32_secret);
	printf("// totp tdata //\n\n");
	
	// Dump data members of struct OTPData hdata
	printf("\\\\ hotp hdata \\\\\n");
	printf("hdata->digits: `%u`\n", hdata->digits);
	printf("hdata->method: `%u`\n", hdata->method);
	printf("hdata->algo: `0x%p`\n", hdata->algo);
	printf("hdata->base32_secret: `%s`\n", hdata->base32_secret);
	printf("hdata->count: `%zu`\n", hdata->count);
	printf("// hotp hdata //\n\n");
	
	printf("Current Time: `%zu`\n\n", get_current_time());
	
	
	
	////////////////////////////////////////////////////////////////
	// URI Example                                                //
	////////////////////////////////////////////////////////////////
	
	char name1[] = "name1";
	char name2[] = "name2";
	char whatever1[] = "account@whatever1.com";
	char whatever2[] = "account@whatever2.com";
	
	// Show example of URIs
	// Caller must free returned strings
	char* uri = otpuri_build_uri(tdata, name1, whatever1, "SHA1");
	printf("TOTP URI: `%s`\n", uri);
	free(uri);
	
	size_t counter = 52; // for example
	hdata->count = counter;
	uri = otpuri_build_uri(hdata, name2, whatever2, "SHA1");
	printf("HOTP URI: `%s`\n\n", uri);
	free(uri);
	
	
	
	////////////////////////////////////////////////////////////////
	// BASE32 Stuff                                               //
	////////////////////////////////////////////////////////////////
	
	// Seed random generator
	// TODO: use a secure random generator
	srand(get_current_time());
	
	const int base32_len = 16; // must be % 8 == 0
	
	// Generate random base32
	char base32_new_secret[base32_len + 1];
	memset(&base32_new_secret, 0, base32_len + 1);
	
	otp_random_base32(base32_len, OTP_DEFAULT_BASE32_CHARS, base32_new_secret);
	base32_new_secret[base32_len] = '\0';
	printf("Random Generated BASE32 Secret: `%s`\n", base32_new_secret);
	
	puts(""); // line break for readability
	
	
	
	////////////////////////////////////////////////////////////////
	// TOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get TOTP for a timeblock
	//   1. Reserve memory and ensure it's null-terminated
	//   2. Generate and load totp key into buffer
	//   3. Check for error
	
	// totp_now
	char tcode[DIGITS+1];
	memset(tcode, 0, DIGITS+1);
	
	int totp_err_1 = totp_now(tdata, tcode);
	if(totp_err_1 == OTP_ERROR)
	{
		fputs("TOTP Error totp_now", stderr);
		return EXIT_FAILURE;
	}
	printf("totp_now() pass=1: `%s` `%d`\n", tcode, totp_err_1);
	
	// totp_at
	char tcode2[DIGITS+1];
	memset(tcode2, 0, DIGITS+1);
	
	int totp_err_2 = totp_at(tdata, 0, 0, tcode2);
	if(totp_err_2 == OTP_ERROR)
	{
		fputs("TOTP Error totp_at", stderr);
		return EXIT_FAILURE;
	}
	printf("totp_at(0, 0) pass=1: `%s` `%d`\n", tcode2, totp_err_2);
	
	// Do a verification for a hardcoded code
	// Won't succeed, this code is for a timeblock far into the past/future
	int tv1 = totp_verify(tdata, "358892", get_current_time(), 4);
	printf("TOTP Verification 1 pass=false: `%s`\n", tv1 == 0 ? "false" : "true");
	
	// Will succeed, timeblock 0 for JBSWY3DPEHPK3PXP == 282760
	int tv2 = totp_verify(tdata, "282760", 0, 4);
	printf("TOTP Verification 2 pass=true: `%s`\n", tv2 == 0 ? "false" : "true");
	
	puts(""); // line break for readability
	
	
	
	////////////////////////////////////////////////////////////////
	// HOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get HOTP for token 1
	//   1. Reserve memory and ensure it's null-terminated
	//   2. Generate and load hotp key into buffer
	//   3. Check for error
	
	char hcode[DIGITS+1];
	memset(hcode, 0, DIGITS+1);
	
	int hotp_err_1 = hotp_at(hdata, 1, hcode);
	if(hotp_err_1 == OTP_ERROR)
	{
		puts("HOTP Error hotp_at");
		return EXIT_FAILURE;
	}
	printf("hotp_at(1) pass=1: `%s` `%d`\n", hcode, hotp_err_1);
	
	// Do a verification for a hardcoded code
	// Won't succeed, 1 for JBSWY3DPEHPK3PXP == 996554
	int hv1 = hotp_compare(hdata, "996555", 1);
	printf("HOTP Verification 1 pass=false: `%s`\n", hv1 == 0 ? "false" : "true");
	
	// Will succeed, 1 for JBSWY3DPEHPK3PXP == 996554
	int hv2 = hotp_compare(hdata, "996554", 1);
	printf("HOTP Verification 2 pass=true: `%s`\n", hv2 == 0 ? "false" : "true");
	
	return EXIT_SUCCESS;
}

