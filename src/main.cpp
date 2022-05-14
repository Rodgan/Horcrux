#include <iostream>
#include <string.h>
#include "horcrux.h"
#include "cipher.h"

void Test(ICipher& cipher)
{
	Horcrux h;
	cipher.GenerateRandomKey();
	char* b64 = h.Base64Encode(cipher.Key, cipher.GetKeyLength());
	char* plain = h.Base64Decode(b64, strlen(b64));
	std::cout << cipher.GetKeyLength() << std::endl;
	std::cout << cipher.Key << std::endl;	
	std::cout << b64 << std::endl;
	std::cout << plain << std::endl;
}
int main()
{

	Aes256 aes;
	Test(aes);
	// std::cout << c. << std::endl;
	
	// std::cout << c.GetAll << std::endl;
	
	// Horcrux h;
	// Aes256 a;
	// a.GenerateRandomKey();

	// // auto key = a.GenerateRandomKey();

	// char* b64 = h.Base64Encode(a.Key, a.GetKeyLength());
	// char* plain = h.Base64Decode(b64, strlen(b64));

	// std::cout << a.GetKeyLength() << std::endl;
	// std::cout << a.Key << std::endl;	
	// std::cout << b64 << std::endl;
	// std::cout << plain << std::endl;

	// std::cout << sizeof(key) << std::endl;
	// auto a = strlen(key);

	// h.Base64Encode(key, );
	
	// h.Encrypt();
	std::cin.get();
	return 0;
}