
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <ctime>

#include "../cotp.hpp"

extern "C" {
	#include <openssl/evp.h>
	#include <openssl/hmac.h>
}


using namespace std;


static const int32_t SHA1_BYTES   = 160 / 8;	// 20
static const int32_t SHA256_BYTES = 256 / 8;	// 32
static const int32_t SHA512_BYTES = 512 / 8;	// 64


// byte_secret is unbase32 key
// byte_string is data to be HMAC'd
int hmac_algo_sha1(const char* byte_secret, const char* byte_string, char* out)
{
	// Output len
	unsigned int len = SHA1_BYTES;
	
	unsigned char* result = HMAC(
			EVP_sha1(),							// algorithm
			(unsigned char*)byte_secret, 10,	// key
			(unsigned char*)byte_string, 8,		// data
			(unsigned char*)out, &len);			// output
	
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
			(unsigned char*)out, &len);			// output
	
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
			(unsigned char*)out, &len);			// output
	
	// Return the HMAC success
	return result == 0 ? 0 : len;
}

uint64_t get_current_time()
{
	return (uint64_t) time(NULL);
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
	
	
	// Create OTPData struct, which decides the environment
	class TOTP tdata {
		BASE32_SECRET,
		hmac_algo_sha1,
		get_current_time,
		DIGITS,
		INTERVAL
	};
		
	class HOTP hdata {
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
	
	// Dump data members of struct OTPData hdata
	OTPData* hdata_s = hdata.data_struct();
	cout << "\\\\ hotp hdata \\\\"		<< endl;
	cout << "hdata->digits: `"			<< hdata_s->digits			<< "`" << endl;
	cout << "hdata->method: `"			<< hdata_s->method			<< "`" << endl;
	cout << "hdata->algo: `"			<< reinterpret_cast<void*>(hdata_s->algo) << "`" << endl;
	cout << "hdata->base32_secret: `"	<< hdata_s->base32_secret	<< "`" << endl;
	cout << "hdata->count: `"			<< hdata_s->count			<< "`" << endl;
	cout << "// hotp hdata //"			<< endl						<< endl;
	
	cout << "Current Time: `" << get_current_time() << "`" << endl;
	
	
	
	////////////////////////////////////////////////////////////////
	// URI Example                                                //
	////////////////////////////////////////////////////////////////
	
	char name1[] = "name1";
	char name2[] = "name2";
	char whatever1[] = "account@whatever1.com";
	char whatever2[] = "account@whatever2.com";
	
	// Show example of URIs
	char* uri = tdata.build_uri(name1, whatever1, "SHA1");
	cout << "TOTP URI: `" << uri << "`" << endl << endl;
	free(uri);
	
	size_t counter = 52; // for example
	hdata_s->count = counter;
	uri = hdata.build_uri(name2, whatever2, "SHA1");
	cout << "HOTP URI: `" << uri << "`" << endl << endl;
	free(uri);
	
	
	
	////////////////////////////////////////////////////////////////
	// BASE32 Stuff                                               //
	////////////////////////////////////////////////////////////////
	
	// Seed random generator
	srand(get_current_time());
	
	const int base32_len = 16; // must be % 8 == 0
	
	// Generate random base32
	char* base32_new_secret = (char*) malloc(base32_len + 1 * sizeof(char));
	OTP::random_base32(base32_len, OTP::default_chars(), base32_new_secret);
	base32_new_secret[base32_len] = '\0';
	cout << "Generated BASE32 Secret: `" << base32_new_secret << "`" << endl;
	
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
	if(totp_err_1 == OTP_ERROR) {
		cout << "TOTP Error totp_now" << endl;
		return 1;
	}
	cout << "totp_now(): `" << tcode << "` `" << totp_err_1 << "`" << endl;
	
	// totp_at
	char tcode2[DIGITS+1];
	memset(tcode2, 0, DIGITS+1);
	int totp_err_2 = tdata.at(0, 0, tcode2);
	if(totp_err_2 == 0) {
		cout << "TOTP Error totp_at" << endl;
		return 1;
	}
	cout << "totp_at(0, 0): `" << tcode2 << "` `" << totp_err_2 << "`" << endl;
	
	// Do a verification for a hardcoded code
	// Won't succeed, this code is for a timeblock far into the past/future
	int tv1 = tdata.verify("358892", get_current_time(), 4);
	cout << "TOTP Verification 1: `" << (tv1 == 0 ? "false" : "true") << "`" << endl;
	
	// Will succeed, timeblock 0 for JBSWY3DPEHPK3PXP == 282760
	int tv2 = tdata.verify("282760", 0, 4);
	cout << "TOTP Verification 2: `" << (tv2 == 0 ? "false" : "true") << "`" << endl;
	
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
		return 1;
	}
	cout << "hotp_at(1): `" << hcode << "`" << "`" << hotp_err_1 << "`" << endl;
	
	// Do a verification for a hardcoded code
	// Won't succeed, 1 for JBSWY3DPEHPK3PXP == 996554
	int hv1 = hdata.compare("996555", 1);
	cout << "HOTP Verification 1: `" << (hv1 == 0 ? "false" : "true") << "`" << endl;
	
	// Will succeed, 1 for JBSWY3DPEHPK3PXP == 996554
	int hv2 = hdata.compare("996554", 1);
	cout << "HOTP Verification 2: `" << (hv2 == 0 ? "false" : "true") << "`" << endl;
	
	// hdata frees its resources at end of scope
	// tdata frees its resources at end of scope
	
	return 0;
}

