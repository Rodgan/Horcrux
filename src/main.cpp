#include <iostream>
#include <string.h>
#include "horcrux.h"
#include "cipher.h"

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

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

	Aes256 aes(CIPHER_MODE::CBC);
	aes.GenerateRandomKey();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, aes.GetEvpCipher(), NULL, aes.GetKey(), aes.GetIV()))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int main()
{
	
	
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

	unsigned char* plaintext = (unsigned char*) "Helloooo";
	int size = 8; //strlen((char*)plaintext);

	Aes256 aes(CIPHER_MODE::CBC);
	aes.GenerateRandomKey();

	int ciphertextLength;
	const char* ciphertext = (const char *) aes.Encrypt(plaintext, size, &ciphertextLength);
	
	// Horcrux h;
	// std::cout << h.Base64Encode(ciphertext, ciphertextLength);

	for(int i = 0; i < ciphertextLength; i++)
	{
		std::cout << ciphertext[i];
	}

	// for (int i = 0; i < ciphertextLength; i++)
	// {
	// 	std::cout << cipherText[i];
	// }

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

	std::cin.get();
	return 0;
}