#include "cipher.h"
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>

// ############ ICipher - Base Class definitions ############
ICipher::ICipher(int keyLength, int ivLength, int blockSize, CIPHER_MODE cipherMode, CIPHER_ALGORITHM cipherAlgorithm)
    : KeyLength(keyLength), IvLength(ivLength), BlockSize(blockSize), Key(new unsigned char[keyLength + ivLength]), CipherMode(cipherMode), CipherAlgorithm(cipherAlgorithm)
{
    GenerateRandomKey();
}
ICipher::~ICipher()
{
    delete Key;
}
void ICipher::GenerateRandomKey()
{
    // Key contains KEY + IV
    // It should be more efficient than storing them in different locations
    
    // If there are other modes that do NOT need the IV, add them here
    if (CipherMode == CIPHER_MODE::ECB)
    {
        IvLength = 0;
        IgnoreIV = true;
    }

    // // Uncomment this for loop for debugging purpose
    // for (int i = 0; i < (KeyLength + IvLength) ; i++)
    // {
    //     Key[i] = i % 256;
    // }
    
    RAND_bytes(Key, KeyLength + IvLength);
}
void ICipher::SetKeyAndIV(unsigned char* buffer)
{
    Key = buffer;
}
unsigned char* ICipher::GetKey()
{
    return Key;
}
unsigned char* ICipher::GetIV()
{
    if (IgnoreIV)
        return NULL;

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
int ICipher::GetCiphertextFixedLength(int& plaintextLength, bool addPadding)
{
    // If padding is not applied, it just returns the array with length equals to bufferLength
    if (!addPadding)
        return plaintextLength;

    int paddingToAdd = BlockSize % plaintextLength;

    if (paddingToAdd == 0)
        paddingToAdd = BlockSize;

    return plaintextLength + paddingToAdd;
}
int ICipher::GetFixedCiphertextLengthFromBase64(unsigned char* base64Ciphertext, int& base64CiphertextLength)
{   
    // Each Base64 digit represents 6 bits
    // If we multiply the length of the base64 buffer by 6,
    // we get the actual number of bits represented by the base64 string.
    // Then, we divide it by 8 and we get the value in bytes.
    // We can now subtract the added padding from the value in bytes and get the
    // actual ciphertext length.
    int base64_char_bits = 6;
    int base64Bytes = (base64CiphertextLength * base64_char_bits) / 8;
    int actualLength = base64Bytes - (base64Bytes % BlockSize);

    return actualLength;
}
int ICipher::Encrypt(unsigned char* plaintext, int& plaintextLength, unsigned char* ciphertext)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    
    int len;
    int ciphertextLength;

    if (!context)
        HandleErrors();
    
    if (1 != EVP_EncryptInit_ex(context, GetEvpCipher(), NULL, GetKey(), GetIV()))
        HandleErrors();

    if(1 != EVP_EncryptUpdate(context, ciphertext, &len, plaintext, plaintextLength))
        HandleErrors();

    ciphertextLength = len;

    if(1 != EVP_EncryptFinal_ex(context, ciphertext + len, &len))
        HandleErrors();

    ciphertextLength += len;

    EVP_CIPHER_CTX_free(context);

    return ciphertextLength;
}
int ICipher::Decrypt(unsigned char* cipertext, int& cipertextLength, unsigned char* plaintext, unsigned char* key, unsigned char* iv)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    
    int len;
    int plaintextLength;

    if (!context)
        HandleErrors();
    
    if (1 != EVP_DecryptInit_ex(context, GetEvpCipher(), NULL, key, iv))
        HandleErrors();

    if(1 != EVP_DecryptUpdate(context, plaintext, &len, cipertext, cipertextLength))
        HandleErrors();

    plaintextLength = len;

    if(1 != EVP_DecryptFinal_ex(context, plaintext + len, &len))
        HandleErrors();

    plaintextLength += len;

    EVP_CIPHER_CTX_free(context);

    return plaintextLength;
}
const EVP_CIPHER* ICipher::GetEvpCipher()
{
    EVP_CIPHER* c = nullptr;
    switch(CipherAlgorithm)
    {
        case CIPHER_ALGORITHM::AES_256:
            if (CipherMode == CIPHER_MODE::CBC) return EVP_aes_256_cbc();
            if (CipherMode == CIPHER_MODE::ECB) return EVP_aes_256_ecb();
        break;

        case CIPHER_ALGORITHM::Data_Encryption_Standard:
            if (CipherMode == CIPHER_MODE::CBC) return EVP_des_cbc();
            if (CipherMode == CIPHER_MODE::ECB) return EVP_des_ecb();
        break;

    }

    // Using cout instead of cerr for testing only
    std::cout << "Cipher algorithm or mode not supported";
    abort();
}

// ############ Derived Class definitions ############
AES256::AES256(CIPHER_MODE cipherMode) : ICipher(KEY_LENGTH, IV_LENGTH, BLOCK_SIZE, cipherMode, CIPHER_ALGORITHM::AES_256)
{

}
DES::DES(CIPHER_MODE cipherMode) : ICipher(KEY_LENGTH, IV_LENGTH, BLOCK_SIZE, cipherMode, CIPHER_ALGORITHM::Data_Encryption_Standard)
{

}
