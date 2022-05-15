#include <iostream>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "horcrux.h"


void Horcrux::Encrypt()
{	
	// std::string text = "Hey!";
	// char * enc_output = Base64Encode(text.c_str(), text.length());
	// std::cout << text << ": " << enc_output << std::endl;
}
void Horcrux::Dencrypt()
{
    std::cout << "Decrypted!\n";
}

char* Horcrux::Base64Encode(unsigned char* input, int length)
{
	const char* convertedInput = reinterpret_cast<const char*>(input);
	return Base64Encode(convertedInput, length);
}
char* Horcrux::Base64Encode(const char* input, int length)
{
	BIO * bmem = NULL;
	BIO * b64 = NULL;
	BUF_MEM * bptr = NULL;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char * buff = (char *)malloc(bptr->length + 1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = 0;

	BIO_free_all(b64);

	return buff;
}
unsigned char* Horcrux::Base64DecodeAsUnsigned(char* input, int length)
{
	return reinterpret_cast<unsigned char*>(Base64Decode(input, length));
}
char * Horcrux::Base64Decode(char * input, int length)
{
	BIO * b64 = NULL;
	BIO * bmem = NULL;
	char * buffer = (char *)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	
	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}