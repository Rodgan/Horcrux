#include "horcrux.h"
#include "cipher.h"
#include "file_manager.h"

#include <iostream>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <string>

Horcrux::~Horcrux()
{
	delete Cipher;
	delete FileManager;
}
void Horcrux::PrintErrorAndAbort(const char* error)
{
    // Change cout in cerr
    std::cout << error << std::endl;
    abort();
}
void Horcrux::Encrypt(char* inputFile, int& chunks, char* outputDirectory)
{
	char* fileNamePrefix = (char*) (std::string(inputFile).substr(std::string(inputFile).find_last_of("/\\") + 1).c_str());

	Cipher -> DisplayAlgorithmInfo();

	std::cout << "Chunks: " << std::to_string(chunks) << std::endl;
	std::cout << "Your file(s) will be saved to " << outputDirectory << std::endl;	
	std::cout << "Generating random key. Please, wait..." << std::endl;
	Cipher -> GenerateRandomKey();
	
	std::cout << "Encrypting your file. Please, wait..." << std::endl;
	FileManager -> EncryptFileAndSave(inputFile, chunks, fileNamePrefix, outputDirectory, *Cipher);

	std::cout << "Encryption completed. To decrypt your file(s) you will need to provide the same settings along with the following key:" << std::endl;

	int keyLength;
	unsigned char* key = Cipher -> GetFullKeyAndIv(keyLength);

	std::cout << Base64Encode(key, keyLength) << std::endl;

	delete[] key;
}
void Horcrux::Decrypt(char** inputFiles, int& numOfFiles, char* outputFile, char* keyInBase64)
{
	Cipher -> DisplayAlgorithmInfo();

	std::cout << "Your file will be saved to " << outputFile << std::endl;	
	std::cout << "Setting the key. Please, wait..." << std::endl;
	Cipher -> SetKeyAndIVFromBase64String(keyInBase64, strlen(keyInBase64));
	
	std::cout << "Decrypting your files. Please, wait..." << std::endl;
	FileManager -> DecryptFilesAndSave(inputFiles, numOfFiles, *Cipher, outputFile);

	std::cout << "Decryption completed!" << std::endl;
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
unsigned char* Horcrux::Base64DecodeAsUnsigned(char* input, int bufferLength, int& outDataRead)
{
	return reinterpret_cast<unsigned char*>(Base64Decode(input, bufferLength, outDataRead));
}
char * Horcrux::Base64Decode(char * input, int bufferLength, int& outDataRead)
{
	BIO * b64 = NULL;
	BIO * bmem = NULL;
	char * buffer = (char *)malloc(bufferLength);
	memset(buffer, 0, bufferLength);

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_new_mem_buf(input, bufferLength);
	bmem = BIO_push(b64, bmem);
	
	outDataRead = BIO_read(bmem, buffer, bufferLength);

	BIO_free_all(bmem);

	return buffer;
}