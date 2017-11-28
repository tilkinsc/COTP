
#include <iostream>
#include <cstdlib>
#include <ctime>	// time
#include <cstring>	// strlen

extern "C" {
	#include <openssl/evp.h>
	#include <openssl/hmac.h>
}

#include "../cotp.hpp"
#include "../otpuri.hpp"


using namespace std;



// byte_secret is unbase32 key
// byte_string is data to be HMAC'd
int hmac_algo_sha1(const char byte_secret[], const char byte_string[], char out[]) {
	
	// output len
	unsigned int len = SHA1_BYTES;
	
	// return the HMAC success
	return HMAC(
			EVP_sha1(),									// algorithm
			(unsigned char*)byte_secret, 10,			// key
			(unsigned char*)byte_string, 8,				// data
			(unsigned char*)out, &len) == 0 ? 0 : 1;	// output
}

int hmac_algo_sha256(const char byte_secret[], const char byte_string[], char out[]) {
	
	// output len
	unsigned int len = SHA256_BYTES;
	
	// return the HMAC success
	return HMAC(
			EVP_sha256(),								// algorithm
			(unsigned char*)byte_secret, 10,			// key
			(unsigned char*)byte_string, 8,				// data
			(unsigned char*)out, &len) == 0 ? 0 : 1;	// output
}

int hmac_algo_sha512(const char byte_secret[], const char byte_string[], char out[]) {
	
	// output len
	unsigned int len = SHA512_BYTES;
	
	// return the HMAC success
	return HMAC(
			EVP_sha512(),								// algorithm
			(unsigned char*)byte_secret, 10,			// key
			(unsigned char*)byte_string, 8,				// data
			(unsigned char*)out, &len) == 0 ? 0 : 1;	// output
}



int main(int argc, char** argv) {
	
	////////////////////////////////////////////////////////////////
	// Initialization Stuff                                       //
	////////////////////////////////////////////////////////////////
	
	const int INTERVAL	= 30;
	const int DIGITS	= 6;
	
	// Base32 secret to utilize
	const char BASE32_SECRET[] = "JBSWY3DPEHPK3PXP";
	
	class TOTP tdata{
		BASE32_SECRET,
		SHA1_BITS,
		hmac_algo_sha1,
		SHA1_DIGEST,
		DIGITS,
		INTERVAL
	};
		
	class HOTP hdata{
		BASE32_SECRET,
		SHA1_BITS,
		hmac_algo_sha1,
		SHA1_DIGEST,
		DIGITS
	};
	
	OTPData* tdata_s = tdata.getDataStruct();
	cout << "\\\\ totp tdata \\\\"		<< endl;
	cout << "tdata->digits: `"			<< tdata_s->digits			<< "`" << endl;
	cout << "tdata->interval: `"		<< tdata_s->interval		<< "`" << endl;
	cout << "tdata->bits: `"			<< tdata_s->bits			<< "`" << endl;
	cout << "tdata->method: `"			<< tdata_s->method			<< "`" << endl;
	cout << "tdata->algo: `"			<< reinterpret_cast<void*>(tdata_s->algo) << "`" << endl;
	cout << "tdata->digest: `"			<< tdata_s->digest			<< "`" << endl;
	cout << "tdata->base32_secret: `"	<< tdata_s->base32_secret	<< "`" << endl;
	cout << "// totp tdata //"			<< endl						<< endl;
	
	OTPData* hdata_s = hdata.getDataStruct();
	cout << "\\\\ hotp hdata \\\\"		<< endl;
	cout << "hdata->digits: `"			<< hdata_s->digits			<< "`" << endl;
	cout << "hdata->interval: `"		<< hdata_s->interval		<< "`" << endl;
	cout << "hdata->bits: `"			<< hdata_s->bits			<< "`" << endl;
	cout << "hdata->method: `"			<< hdata_s->method			<< "`" << endl;
	cout << "hdata->algo: `"			<< reinterpret_cast<void*>(hdata_s->algo) << "`" << endl;
	cout << "hdata->digest: `"			<< hdata_s->digest			<< "`" << endl;
	cout << "hdata->base32_secret: `"	<< hdata_s->base32_secret	<< "`" << endl;
	cout << "// hotp hdata //"			<< endl						<< endl;
	
	cout << "Current Time: `" << time(NULL) << "`" << endl;
	
	
	
	////////////////////////////////////////////////////////////////
	// URI Example                                                //
	////////////////////////////////////////////////////////////////
	
	char name1[] = "name1";
	char name2[] = "name2";
	char whatever1[] = "account@whatever1.com";
	char whatever2[] = "account@whatever2.com";
	
	char* uri = OTPURI::build_uri(tdata.getDataStruct(), name1, whatever1, 0);
	cout << "TOTP URI: `" << uri << "`" << endl << endl;
	free(uri);
	
	size_t counter = 52;
	uri = OTPURI::build_uri(hdata.getDataStruct(), name2, whatever2, counter);
	cout << "HOTP URI: `" << uri << "`" << endl << endl;
	free(uri);
	
	
	
	////////////////////////////////////////////////////////////////
	// BASE32 Stuff                                               //
	////////////////////////////////////////////////////////////////
	
	// Seed random generator
	srand(time(NULL));
	
	const int base32_len = 16;
	
	// Generate random base32
	char* base32_new_secret = (char*) malloc(base32_len + 1 * sizeof(char));
	OTP::random_base32(base32_len, OTP::getDefaultChars(), base32_new_secret);
	base32_new_secret[base32_len] = '\0';
	cout << "Generated BASE32 Secret: `" << base32_new_secret << "`" << endl;
	
	cout << endl; // line break for readability
	
	
	////////////////////////////////////////////////////////////////
	// TOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get TOTP for a time block
	//   1. Reserve memory and ensure it's null-terminated
	//   2. Generate and load totp key into tcode
	//   3. Check for error
	//   4. Free data
	
	// TOTP now
	char* tcode = (char*) calloc(DIGITS+1, sizeof(char));
	int totp_err_1 = tdata.now(tcode);
	if(totp_err_1 == 0) {
		cout << "TOTP Error 1" << endl;
		return 1;
	}
	cout << "TOTP Generated: `" << tcode << "` `" << totp_err_1 << "`" << endl;
	free(tcode);
	
	
	// TOTP at
	char* tcode2 = (char*) calloc(DIGITS+1, sizeof(char));
	int totp_err_2 = tdata.at(1, 0, tcode2);
	if(totp_err_2 == 0) {
		cout << "TOTP Error 2" << endl;
		return 1;
	}
	cout << "TOTP Generated: `" << tcode2 << "` `" << totp_err_2 << "`" << endl;
	free(tcode2);
	
	
	// Do a verification for a hardcoded code
	
	// Won't succeed, this code is for a timeblock far into the past
	int tv1 = tdata.verify(576203, time(NULL), 4);
	
	// Will succeed, timeblock 0 for JBSWY3DPEHPK3PXP == 282760
	int tv2 = tdata.verify(282760, 0, 4);
	cout << "TOTP Verification 1: `" << (tv1 == 0 ? "false" : "true") << "`" << endl;
	cout << "TOTP Verification 2: `" << (tv2 == 0 ? "false" : "true") << "`" << endl;
	
	cout << endl; // line break for readability
	
	
	////////////////////////////////////////////////////////////////
	// HOTP Stuff                                                 //
	////////////////////////////////////////////////////////////////
	
	// Get HOTP for token 1
	//   1. Reserve memory and ensure it's null-terminated
	//   2. Generate and load hotp key into hcode
	//   3. Check for error
	//   3. Free data
	char* hcode = (char*) calloc(8+1, sizeof(char));
	int hotp_err_1 = hdata.at(1, hcode);
	if(hotp_err_1 == 0) {
		cout << "HOTP Error 1" << endl;
		return 1;
	}
	cout << "HOTP Generated at 1: `" << hcode << "`" << endl;
	free(hcode);
	
	// Do a verification for a hardcoded code
	// Will succeed, 1 for JBSWY3DPEHPK3PXP == 996554
	int hv = hdata.verify(996554, 1);
	cout << "HOTP Verification 1: `" << (hv == 0 ? "false" : "true") << "`" << endl;
	
	
	
	tdata.free();
	hdata.free();
	
	return 0;
}



