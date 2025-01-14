
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
int hmac_algo_sha1(const char* byte_secret, int key_length, const char* byte_string, char* out)
{
	// Output len
	unsigned int len = SHA1_BYTES;
	
	unsigned char* result = HMAC(
		EVP_sha1(),									// algorithm
		(unsigned char*)byte_secret, key_length,	// key
		(unsigned char*)byte_string, 8,				// data
		(unsigned char*)out,						// output
		&len										// output length
	);
	
	// Return the HMAC success
	return result == 0 ? 0 : len;
}

int hmac_algo_sha256(const char* byte_secret, int key_length, const char* byte_string, char* out)
{
	// Output len
	unsigned int len = SHA256_BYTES;
	
	unsigned char* result = HMAC(
		EVP_sha256(),								// algorithm
		(unsigned char*)byte_secret, key_length,	// key
		(unsigned char*)byte_string, 8,				// data
		(unsigned char*)out,						// output
		&len										// output length
	);
	
	// Return the HMAC success
	return result == 0 ? 0 : len;
}

int hmac_algo_sha512(const char* byte_secret, int key_length, const char* byte_string, char* out)
{
	// Output len
	unsigned int len = SHA512_BYTES;
	
	unsigned char* result = HMAC(
		EVP_sha512(),								// algorithm
		(unsigned char*)byte_secret, key_length,	// key
		(unsigned char*)byte_string, 8,				// data
		(unsigned char*)out,						// output
		&len										// output length
	);
	
	// Return the HMAC success
	return result == 0 ? 0 : len;
}

uint64_t get_current_time()
{
	uint64_t milliseconds = 0;
	
#if defined(_WIN32)
	FILETIME fileTime;
	GetSystemTimeAsFileTime(&fileTime);
	
	ULARGE_INTEGER largeInteger;
	largeInteger.LowPart = fileTime.dwLowDateTime;
	largeInteger.HighPart = fileTime.dwHighDateTime;
	
	milliseconds = (largeInteger.QuadPart - 116444736000000000ULL) / 10000000ULL;
#elif defined(__linux__)
	struct timeval sys_time;
	gettimeofday(&sys_time, NULL);
	
	milliseconds = sys_time.tv_sec;
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
	const char BASE32_SECRET[] = "JBSWY3DPEHPK3PXP"; // JBSWY3DPEHPK3PXP 3E56263A4A655ED7
	
	// Base32 secret to utilize with padding
	const char BASE32_SECRET_PADDING[] = "ORSXG5BRGIZXIZLTOQ2DKNRXHA4XIZLTOQYQ====";
	
	OTPData odata1;
	memset(&odata1, 0, sizeof(OTPData));
	
	OTPData odata_padding;
	memset(&odata_padding, 0, sizeof(OTPData));
	
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
	
	OTPData* tdata_padding = totp_new(
		&odata_padding,
		BASE32_SECRET_PADDING,
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
	
	// Dump data members of struct OTPData tdata_padding
	printf("\\\\ totp tdata_padding \\\\\n");
	printf("tdata_padding->digits: `%u`\n", tdata_padding->digits);
	printf("tdata_padding->interval: `%u`\n", tdata_padding->interval);
	printf("tdata_padding->method: `%u`\n", tdata_padding->method);
	printf("tdata_padding->algo: `0x%p`\n", tdata_padding->algo);
	printf("tdata_padding->time: `0x%p`\n", tdata_padding->time);
	printf("tdata_padding->base32_secret: `%s`\n", tdata_padding->base32_secret);
	printf("// totp tdata_padding //\n\n");
	
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
	
	size_t totp_uri_max = otpuri_strlen(tdata, name1, whatever1, "SHA1");
	size_t hotp_uri_max = otpuri_strlen(hdata, name2, whatever2, "SHA1");
	printf("Maximum buffer size for TOTP: `%zu`\n", totp_uri_max);
	printf("Maximum buffer size for HOTP: `%zu`\n\n", hotp_uri_max);
	
	char totp_uri[totp_uri_max + 1];
	memset(totp_uri, 0, totp_uri_max + 1);
	otpuri_build_uri(tdata, name1, whatever1, "SHA1", totp_uri);
	printf("TOTP URI (%zu bytes): `%s`\n", strlen(totp_uri), totp_uri);
	
	size_t counter = 52; // for example
	hdata->count = counter;
	
	char hotp_uri[hotp_uri_max + 1];
	memset(hotp_uri, 0, hotp_uri_max + 1);
	otpuri_build_uri(hdata, name2, whatever2, "SHA1", hotp_uri);
	printf("HOTP URI (%zu bytes): `%s`\n\n", strlen(hotp_uri), hotp_uri);
	
	
	
	////////////////////////////////////////////////////////////////
	// BASE32 Stuff                                               //
	////////////////////////////////////////////////////////////////
	
	const int base32_len = 16; // must be % 8 == 0
	
	// Generate random base32
	char base32_new_secret[base32_len + 1];
	memset(&base32_new_secret, 0, base32_len + 1);
	
	int random_otp_err = otp_random_base32(base32_len, base32_new_secret);
	printf("Random Generated BASE32 Secret pass=1: `%s` `%d`\n", base32_new_secret, random_otp_err);
	
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
	// TOTP Stuff (Padding)                                       //
	////////////////////////////////////////////////////////////////
	
	// Get TOTP for a timeblock
	//   1. Reserve memory and ensure it's null-terminated
	//   2. Generate and load totp key into buffer
	//   3. Check for error
	
	// totp_now
	char tcode3[DIGITS+1];
	memset(tcode3, 0, DIGITS+1);
	
	int totp_err_3 = totp_now(tdata_padding, tcode3);
	if(totp_err_3 == OTP_ERROR)
	{
		fputs("TOTP Error totp_now (padding)", stderr);
		return EXIT_FAILURE;
	}
	printf("totp_now() (padding) pass=1: `%s` `%d`\n", tcode3, totp_err_3);
	
	// totp_at
	char tcode4[DIGITS+1];
	memset(tcode4, 0, DIGITS+1);
	
	int totp_err_4 = totp_at(tdata_padding, 0, 0, tcode4);
	if(totp_err_4 == OTP_ERROR)
	{
		fputs("TOTP Error totp_at (padding)", stderr);
		return EXIT_FAILURE;
	}
	printf("totp_at(0, 0) (padding) pass=1: `%s` `%d`\n", tcode4, totp_err_4);
	
	// Do a verification for a hardcoded code
	// Won't succeed, this code is for a timeblock far into the past/future
	int tv3 = totp_verify(tdata_padding, "122924", get_current_time(), 4);
	printf("TOTP Verification 1 (padding) pass=false: `%s`\n", tv3 == 0 ? "false" : "true");
	
	// Will succeed, timeblock 0 for 'ORSXG5BRGIZXIZLTOQ2DKNRXHA4XIZLTOQYQ====' == 570783
	int tv4 = totp_verify(tdata_padding, "570783", 0, 4);
	printf("TOTP Verification 2 (padding) pass=true: `%s`\n", tv4 == 0 ? "false" : "true");
	
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

