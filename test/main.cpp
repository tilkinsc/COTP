
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <chrono>

#include "../cotp.hpp"

extern "C"
{
	#include <openssl/evp.h>
	#include <openssl/hmac.h>
}


using namespace std;
using namespace COTP;


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
		EVP_sha1(),							// algorithm
		(unsigned char*)byte_secret, key_length,	// key
		(unsigned char*)byte_string, 8,		// data
		(unsigned char*)out,				// output
		&len								// output length
	);
	
	// Return the HMAC success
	return result == 0 ? 0 : len;
}


int hmac_algo_sha256(const char* byte_secret, int key_length, const char* byte_string, char* out)
{
	// Output len
	unsigned int len = SHA256_BYTES;
	
	unsigned char* result = HMAC(
		EVP_sha256(),						// algorithm
		(unsigned char*)byte_secret, key_length,	// key
		(unsigned char*)byte_string, 8,		// data
		(unsigned char*)out,				// output
		&len								// output length
	);
	
	// Return the HMAC success
	return result == 0 ? 0 : len;
}

int hmac_algo_sha512(const char* byte_secret, int key_length, const char* byte_string, char* out)
{
	// Output len
	unsigned int len = SHA512_BYTES;
	
	unsigned char* result = HMAC(
		EVP_sha512(),						// algorithm
		(unsigned char*)byte_secret, key_length,	// key
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
	using namespace std::chrono;
	
	auto now = system_clock::now();
	auto dur = now.time_since_epoch();
	
	return duration_cast<chrono::seconds>(dur).count();
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
	
	// Base32 secret to utilize with padding
	const char BASE32_SECRET_PADDING[] = "ORSXG5BRGIZXIZLTOQ2DKNRXHA4XIZLTOQYQ====";
	
	OTPData odata1;
	memset(&odata1, 0, sizeof(OTPData));
	
	OTPData odata_padding;
	memset(&odata_padding, 0, sizeof(OTPData));
	
	OTPData odata2;
	memset(&odata2, 0, sizeof(OTPData));
	
	// Create OTPData struct, which decides the environment
	class TOTP tdata
	{
		&odata1,
		BASE32_SECRET,
		hmac_algo_sha1,
		get_current_time,
		DIGITS,
		INTERVAL
	};
	
	class TOTP tdata_padding
	{
		&odata_padding,
		BASE32_SECRET_PADDING,
		hmac_algo_sha1,
		get_current_time,
		DIGITS,
		INTERVAL
	};
	
	class HOTP hdata
	{
		&odata2,
		BASE32_SECRET,
		hmac_algo_sha1,
		DIGITS,
		0
	};
	
	// Dump data members of struct OTPData tdata
	OTPData* tdata_s = tdata.data_struct();
	cout << "\\\\ totp tdata \\\\"		<< endl;
	cout << "tdata->digits: `"			<< tdata_s->digits			<< "`" << endl;
	cout << "tdata->interval: `"		<< tdata_s->interval		<< "`" << endl;
	cout << "tdata->method: `"			<< tdata_s->method			<< "`" << endl;
	cout << "tdata->algo: `"			<< reinterpret_cast<void*>(tdata_s->algo) << "`" << endl;
	cout << "tdata->time: `"			<< reinterpret_cast<void*>(tdata_s->time) << "`" << endl;
	cout << "tdata->base32_secret: `"	<< tdata_s->base32_secret	<< "`" << endl;
	cout << "// totp tdata //"			<< endl						<< endl;
	
	// Dump data members of struct OTPData tdata_padding
	OTPData* tdata_padding_s = tdata.data_struct();
	cout << "\\\\ totp tdata_padding \\\\"		<< endl;
	cout << "tdata_padding->digits: `"			<< tdata_padding_s->digits			<< "`" << endl;
	cout << "tdata_padding->interval: `"		<< tdata_padding_s->interval		<< "`" << endl;
	cout << "tdata_padding->method: `"			<< tdata_padding_s->method			<< "`" << endl;
	cout << "tdata_padding->algo: `"			<< reinterpret_cast<void*>(tdata_padding_s->algo) << "`" << endl;
	cout << "tdata_padding->time: `"			<< reinterpret_cast<void*>(tdata_padding_s->time) << "`" << endl;
	cout << "tdata_padding->base32_secret: `"	<< tdata_padding_s->base32_secret	<< "`" << endl;
	cout << "// totp tdata_padding //"			<< endl								<< endl;
	
	
	// Dump data members of struct OTPData hdata
	OTPData* hdata_s = hdata.data_struct();
	cout << "\\\\ hotp hdata \\\\"		<< endl;
	cout << "hdata->digits: `"			<< hdata_s->digits			<< "`" << endl;
	cout << "hdata->method: `"			<< hdata_s->method			<< "`" << endl;
	cout << "hdata->algo: `"			<< reinterpret_cast<void*>(hdata_s->algo) << "`" << endl;
	cout << "hdata->base32_secret: `"	<< hdata_s->base32_secret	<< "`" << endl;
	cout << "hdata->count: `"			<< hdata_s->count			<< "`" << endl;
	cout << "// hotp hdata //"			<< endl						<< endl;
	
	cout << "Current Time: `" << get_current_time() << "`" << endl << endl;
	
	
	
	////////////////////////////////////////////////////////////////
	// URI Example                                                //
	////////////////////////////////////////////////////////////////
	
	char name1[] = "name1";
	char name2[] = "name2";
	char whatever1[] = "account@whatever1.com";
	char whatever2[] = "account@whatever2.com";
	
	size_t totp_uri_max = tdata.uri_strlen(name1, whatever1, "SHA1");
	size_t hotp_uri_max = hdata.uri_strlen(name2, whatever2, "SHA1");
	cout << "Maximum buffer size for TOTP: `" << totp_uri_max << "`" << endl;
	cout << "Maximum buffer size for HOTP: `" << hotp_uri_max << "`" << endl << endl;
	
	char totp_uri[totp_uri_max + 1];
	memset(totp_uri, 0, totp_uri_max + 1);
	tdata.build_uri(name1, whatever1, "SHA1", totp_uri);
	cout << "TOTP URI: `" << totp_uri << "`" << endl;
	
	size_t counter = 52; // for example
	hdata_s->count = counter;
	
	char hotp_uri[hotp_uri_max + 1];
	memset(hotp_uri, 0, hotp_uri_max + 1);
	hdata.build_uri(name2, whatever2, "SHA1", hotp_uri);
	cout << "HOTP URI: `" << hotp_uri << "`" << endl << endl;
	
	
	
	////////////////////////////////////////////////////////////////
	// BASE32 Stuff                                               //
	////////////////////////////////////////////////////////////////
	
	const int base32_len = 16; // must be % 8 == 0
	
	// Generate random base32
	char base32_new_secret[base32_len + 1];
	memset(&base32_new_secret, 0, base32_len + 1);
	
	int random_otp_err = OTP::random_base32(base32_len, base32_new_secret);
	cout << "Random Generated BASE32 Secret pass=1: `" << base32_new_secret << "` `" << random_otp_err << "`" << endl;
	
	cout << endl; // line break for readability
	
	
	
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
	
	int totp_err_1 = tdata.now(tcode);
	if(totp_err_1 == OTP_ERROR)
	{
		cout << "TOTP Error totp_now (padding)" << endl;
		return EXIT_FAILURE;
	}
	cout << "totp_now() (padding) pass=1: `" << tcode << "` `" << totp_err_1 << "`" << endl;
	
	// totp_at
	char tcode2[DIGITS+1];
	memset(tcode2, 0, DIGITS+1);
	
	int totp_err_2 = tdata.at(0, 0, tcode2);
	if(totp_err_2 == 0)
	{
		cout << "TOTP Error totp_at (padding)" << endl;
		return EXIT_FAILURE;
	}
	cout << "totp_at(0, 0) (padding) pass=1: `" << tcode2 << "` `" << totp_err_2 << "`" << endl;
	
	// Do a verification for a hardcoded code
	// Won't succeed, this code is for a timeblock far into the past/future
	int tv1 = tdata.verify("358892", get_current_time(), 4);
	cout << "TOTP Verification 1 (padding) pass=false: `" << (tv1 == 0 ? "false" : "true") << "`" << endl;
	
	// Will succeed, timeblock 0 for JBSWY3DPEHPK3PXP == 282760
	int tv2 = tdata.verify("282760", 0, 4);
	cout << "TOTP Verification 2 (padding) pass=true: `" << (tv2 == 0 ? "false" : "true") << "`" << endl;
	
	cout << endl; // line break for readability
	
	
	
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
	
	int totp_err_3 = tdata_padding.now(tcode3);
	if(totp_err_3 == OTP_ERROR)
	{
		cout << "TOTP Error totp_now" << endl;
		return EXIT_FAILURE;
	}
	cout << "totp_now() pass=1: `" << tcode3 << "` `" << totp_err_3 << "`" << endl;
	
	// totp_at
	char tcode4[DIGITS+1];
	memset(tcode4, 0, DIGITS+1);
	
	int totp_err_4 = tdata_padding.at(0, 0, tcode4);
	if(totp_err_4 == 0)
	{
		cout << "TOTP Error totp_at" << endl;
		return EXIT_FAILURE;
	}
	cout << "totp_at(0, 0) pass=1: `" << tcode4 << "` `" << totp_err_4 << "`" << endl;
	
	// Do a verification for a hardcoded code
	// Won't succeed, this code is for a timeblock far into the past/future
	int tv3 = tdata_padding.verify("358892", get_current_time(), 4);
	cout << "TOTP Verification 1 pass=false: `" << (tv3 == 0 ? "false" : "true") << "`" << endl;
	
	// Will succeed, timeblock 0 for 'ORSXG5BRGIZXIZLTOQ2DKNRXHA4XIZLTOQYQ====' == 570783
	int tv4 = tdata_padding.verify("570783", 0, 4);
	cout << "TOTP Verification 2 pass=true: `" << (tv4 == 0 ? "false" : "true") << "`" << endl;
	
	cout << endl; // line break for readability
	
	
	
	////////////////////////////////////////////////////////////////
	// HOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get HOTP for token 1
	//   1. Reserve memory and ensure it's null-terminated
	//   2. Generate and load hotp key into buffer
	//   3. Check for error
	
	char hcode[DIGITS+1];
	memset(hcode, 0, DIGITS+1);
	
	int hotp_err_1 = hdata.at(1, hcode);
	if(hotp_err_1 == 0) {
		cout << "HOTP Error hotp_at" << endl;
		return EXIT_FAILURE;
	}
	cout << "hotp_at(1) pass=1: `" << hcode << "`" << " `" << hotp_err_1 << "`" << endl;
	
	// Do a verification for a hardcoded code
	// Won't succeed, 1 for JBSWY3DPEHPK3PXP == 996554
	int hv1 = hdata.compare("996555", 1);
	cout << "HOTP Verification 1 pass=false: `" << (hv1 == 0 ? "false" : "true") << "`" << endl;
	
	// Will succeed, 1 for JBSWY3DPEHPK3PXP == 996554
	int hv2 = hdata.compare("996554", 1);
	cout << "HOTP Verification 2 pass=true: `" << (hv2 == 0 ? "false" : "true") << "`" << endl;
	
	return EXIT_SUCCESS;
}

