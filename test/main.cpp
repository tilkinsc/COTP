
#include "../cotp.hpp"

extern "C" {
	#include <openssl/evp.h>
	#include <openssl/hmac.h>
}

#include <iostream>
#include <string.h>

using namespace std;

int hmac_algo(const char* byte_secret, const char* byte_string, char* out) {
	
	unsigned int len = 20;
	
	return HMAC(EVP_sha1(), (const unsigned char*)byte_secret, 10, (const unsigned char*)byte_string, 8, (unsigned char*)out, &len) == NULL ? 0 : 1;
	
}

int main(void) {
	
	class TOTP totp{"JBSWY3DPEHPK3PXP", 160, hmac_algo, "sha1", 6, 30};
	
	char code[7];
	memset(code, 0, 7);
	int ncode = totp.now(code);
	
	cout << code << endl;
	cout << ncode << endl;
	
	return 0;
}



