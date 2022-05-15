#include "horcrux.h"
#include "cipher.h"
#include "file_manager.h"

#include <iostream>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

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
	char* input = "C:\\Enc\\task.pdf";
	int chunks = 9;

	LocalDisk disk;
	AES256 aes(CIPHER_MODE::CBC);

	disk.EncryptFile(input, chunks, "task", "C:\\Enc\\", aes);

	// char** files = new char*[5] { 
	// 	"C:\\Enc\\task_0", 
	// 	"C:\\Enc\\task_1", 
	// 	"C:\\Enc\\task_2", 
	// 	"C:\\Enc\\task_3", 
	// 	"C:\\Enc\\task_4", 
	// 	};

	
	char** files = new char*[9] { 
		"C:\\Enc\\task_0", 
		"C:\\Enc\\task_1", 
		"C:\\Enc\\task_2", 
		"C:\\Enc\\task_3", 
		"C:\\Enc\\task_4", 
		"C:\\Enc\\task_5", 
		"C:\\Enc\\task_6", 
		"C:\\Enc\\task_7", 
		"C:\\Enc\\task_8"};

	char* output = "C:\\Enc\\decr.txt";
	disk.DecryptFilesAndSave(files, 9, aes, output);

	// LocalDisk disk;
	
	// char* files[4] = { "C:\\non_esiste", "C:\\esiste_naaaah", "C:\\dev\\Horcrux\\task.pdf", "C:\\dev\\Horcrux\\make.cmd" };

	// char** ptr = &(files[2]);

	// disk.ReadFiles(ptr, 2);

    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */


    /* A 256 bit key */
    // unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    // /* A 128 bit IV */
    // unsigned char *iv = (unsigned char *)"0123456789012345";



    // /* Message to be encrypted */
    // unsigned char *plaintext =
    //     (unsigned char *)"The quick brown fox jumps over the lazy dog";

    // /*
    //  * Buffer for ciphertext. Ensure the buffer is long enough for the
    //  * ciphertext which may be longer than the plaintext, depending on the
    //  * algorithm and mode.
    //  */
    // unsigned char ciphertext[128];

    // /* Buffer for the decrypted text */
    // unsigned char decryptedtext[128];

    // int decryptedtext_len, ciphertext_len;

    // /* Encrypt the plaintext */
    // ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
    //                           ciphertext);

    // /* Do something useful with the ciphertext here */
    // printf("Ciphertext is:\n");
    // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

	// unsigned char* plaintext = (unsigned char*) "Yo I'm Ciccio Cappuccio ò.ò";
	// int size = strlen((char*)plaintext);

	// DES aes(CIPHER_MODE::CBC);

	// bool addPadding = true;
	// unsigned char* ciphertext = new unsigned char[aes.GetCiphertextFixedLength(size, addPadding)]; //aes.PrepareCiphertextPointer(plaintext, size, addPadding);

	// int ciphertextLength = aes.Encrypt(plaintext, size, ciphertext);
	
	// Horcrux h;
	// char* b64Encoded = h.Base64Encode(ciphertext, ciphertextLength);
	// unsigned char* b64Decoded = h.Base64DecodeAsUnsigned(b64Encoded, strlen(b64Encoded));

	// std::cout << "Key only: " << h.Base64Encode(aes.GetKey(), aes.GetKeyLength()) << std::endl;
	// std::cout << "IV only: " << h.Base64Encode(aes.GetIV(), aes.GetIVLength()) << std::endl;

	// std::cout << "Plaintext: " << plaintext << std::endl;
	// std::cout << "Ciphertext: ";

	// for (int i = 0; i < ciphertextLength; i++)
	// {
	// 	std::cout << ciphertext[i];
	// }
	// std::cout << std::endl;

	// std::cout << "Ciphertext length: "  << ciphertextLength << std::endl;
	// std::cout << "Ciphertext in base64: " << b64Encoded << std::endl;

	// int len = strlen(b64Encoded);
	// int actualLength = aes.GetFixedCiphertextLengthFromBase64(b64Decoded, len);
	// unsigned char* ptext2 = new unsigned char[actualLength]; // aes.PreparePlaintextPointer(b64Decoded, len, true);
	// int plaintextLength = aes.Decrypt(b64Decoded, actualLength, ptext2, aes.GetKey(), aes.GetIV());

	// std::cout << "Plaintext length: " << plaintextLength << std::endl;
	// std::cout << "Text: ";
	// for(int i = 0; i < plaintextLength; i++)
	// {
	// 	std::cout << ptext2[i];
	// }
	// std::cout << std::endl;



	// std::cout << "All: ";
	
	// for (int i = 0; i < aes.GetKeyLength() + aes.GetIVLength(); i++)
	// {
	// 	std::cout << aes.Key[i];
	// }
	// std::cout << std::endl;
	
	// unsigned char* key = aes.GetKey();
	// unsigned char* iv = aes.GetIV();
	// std::cout << "Key: ";
	// for(int i = 0; i < aes.GetKeyLength(); i++)
	// {
	// 	std::cout << key[i];
	// }
	// std::cout << std::endl;
	// std::cout << "IV: ";
	// for(int i = 0; i < aes.GetIVLength(); i++)
	// {
	// 	std::cout << iv[i];
	// }
	// std::cout << std::endl;

	return 0;
}