#include "cipher.h"
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>

// ############ ICipher - Base Class definitions ############
ICipher::ICipher(int keyLength, int ivLength, CIPHER_MODE cipherMode, CIPHER_ALGORITHM cipherAlgorithm)
    : KeyLength(keyLength), IvLength(ivLength), Key(new unsigned char[keyLength + ivLength]), CipherMode(cipherMode), CipherAlgorithm(cipherAlgorithm)
{

}
ICipher::~ICipher()
{
    delete Key;
}
void ICipher::GenerateRandomKey()
{
    // Key contains KEY + IV
    // It should be more efficient than storing them in different locations
    for (int i = 0; i < (KeyLength + IvLength) ; i++)
    {
        Key[i] = i % 255;
    }
    //RAND_bytes(Key, KeyLength + IvLength);
}
void ICipher::SetKey(unsigned char* key)
{
    Key = key;
}
unsigned char* ICipher::GetKey()
{
    return Key;
}
unsigned char* ICipher::GetIV()
{
    return Key + KeyLength;
}
int& ICipher::GetKeyLength()
{
    return KeyLength;
}
int& ICipher::GetIVLength()
{
    return IvLength;
}
void ICipher::HandleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}
const EVP_CIPHER* ICipher::GetEvpCipher()
{
    EVP_CIPHER* c = nullptr;

    switch(CipherAlgorithm)
    {
        case CIPHER_ALGORITHM::AES_256:
            if (CipherMode == CIPHER_MODE::CBC) return EVP_aes_256_cbc();
        break;;
    }

    std::cout << "Cipher algorithm or mode not supported";
    abort();
}
unsigned char* ICipher::Encrypt(unsigned char* buffer, int bufferLength, int* outCiphertextLength)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    
    unsigned char* ciphertext;
    int len;
    int ciphertextLength;

    if (!context)
        HandleErrors();
    
    if (1 != EVP_EncryptInit_ex(context, GetEvpCipher(), NULL, GetKey(), GetIV()))
        HandleErrors();

    if(1 != EVP_EncryptUpdate(context, ciphertext, &len, buffer, bufferLength))
        HandleErrors();

    ciphertextLength = len;

    if(1 != EVP_EncryptFinal_ex(context, ciphertext + len, &len))
        HandleErrors();

    ciphertextLength += len;
    *outCiphertextLength = ciphertextLength;

    EVP_CIPHER_CTX_free(context);

    return ciphertext;
}
void ICipher::Decrypt(char* buffer)
{

}
// ############ AES256 - Derived Class definitions ############
#pragma region AES-256
Aes256::Aes256(CIPHER_MODE cipherMode) : ICipher(KEY_LENGTH, IV_LENGTH, cipherMode, CIPHER_ALGORITHM::AES_256)
{

}



void Aes256::Decrypt(char* buffer)
{
    
}
#pragma endregion