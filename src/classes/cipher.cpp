#include "cipher.h"
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>

// ############ ICipher - Base Class definitions ############
ICipher::ICipher(int keyLength, CIPHER_MODE cipherMode, CIPHER_ALGORITHM cipherAlgorithm)
    : KeyLength(keyLength), Key(new unsigned char[keyLength]), CipherMode(cipherMode), CipherAlgorithm(cipherAlgorithm)
{
    
}
ICipher::~ICipher()
{
    delete Key;
}
void ICipher::GenerateRandomKey()
{
    RAND_bytes(Key, KeyLength);
}
void ICipher::SetKey(unsigned char* key, int keyLength)
{
    Key = key;
    KeyLength = keyLength;
}
int& ICipher::GetKeyLength()
{
    return KeyLength;
}
void ICipher::HandleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

// ############ AES256 - Derived Class definitions ############
#pragma region AES-256
Aes256::Aes256(CIPHER_MODE cipherMode = CIPHER_MODE::CBC) : ICipher(KEY_LENGTH + IV_LENGTH, cipherMode, CIPHER_ALGORITHM::AES_256)
{

}

void Aes256::Encrypt(char* buffer)
{
    // unsigned char ciphertext[BLOCK_SIZE_IN_BIT];

    // EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    
    // // If initialization fails, terminate
    // if (!context)
    //     HandleErrors();
    

}
void Aes256::Decrypt(char* buffer)
{
    
}
#pragma endregion