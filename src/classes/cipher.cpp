#include "horcrux.h"
#include "cipher.h"
#include "file_manager.h"

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <string>

namespace Cubbit
{
    // ############ ICipher - Base Class definitions ############
    ICipher::ICipher(int keyLength, int ivLength, int blockSize, CIPHER_MODE cipherMode, CIPHER_ALGORITHM cipherAlgorithm)
        : KeyLength(keyLength), IvLength(ivLength), BlockSize(blockSize), CipherMode(cipherMode), CipherAlgorithm(cipherAlgorithm)
    {
        // If there are other modes that do NOT need the IV, add them here
        if (CipherMode == CIPHER_MODE::ECB)
        {
            IvLength = 0;
            IgnoreIV = true;
        }

        Key = new unsigned char[KeyLength + IvLength];
    }
    ICipher::~ICipher()
    {
        delete Key;
    }
    void ICipher::GenerateRandomKey()
    {
        // Key contains KEY + IV
        // It should be more efficient than storing them in different locations
        
        // Uncomment this for loop for debugging purpose
        // for (int i = 0; i < (KeyLength + IvLength) ; i++)
        // {
        //     Key[i] = i % 256;
        // }
        
        RAND_bytes(Key, KeyLength + IvLength);
    }
    void ICipher::SetKeyAndIVFromBase64String(char* buffer, int bufferLength)
    {
        int dataRead;
        unsigned char* key = Horcrux::Base64DecodeAsUnsigned(buffer, bufferLength, dataRead);

        if (dataRead != KeyLength + IvLength)
        {
            std::string message = "Unable to set Key and IV. Expected a buffer of " + std::to_string(KeyLength + IvLength) + " bytes. Your key is " + std::to_string(dataRead) + " bytes.";
            Horcrux::PrintErrorAndAbort(message.c_str());
        }
        
        Key = key;
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
    unsigned char* ICipher::GetFullKeyAndIv(int& outTotalLength)
    {
        outTotalLength = KeyLength + IvLength;
        return Key;
    }
    void ICipher::HandleErrors()
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    void ICipher::DisplayAlgorithmInfo()
    {
        std::cout << "=====ALGORITHM INFO=====" << std::endl;
        std::cout << "Algorithm: ";

        switch(CipherAlgorithm)
        {
            case CIPHER_ALGORITHM::AES_256:
                std::cout << "AES256 (Advanced Encryption Standard)";
            break;
            case CIPHER_ALGORITHM::Data_Encryption_Standard:
                std::cout << "DES (Data Encryption Standard)";
            break;
            default:
                std::cout << "Algorithm not recognized";
            break;
        }

        std::cout << std::endl << "Mode: ";

        switch(CipherMode)
        {
            case CIPHER_MODE::CBC:
                std::cout << "CBC (Cipher Block Chaining)";
            break;

            case CIPHER_MODE::ECB:
                std::cout << "ECB (Electronic Code Book)";
            break;
        
            default:
                std::cout << "Mode not recognized";
            break;
        }

        std::cout << std::endl << "Key Length: " << std::to_string(KeyLength);
        std::cout << std::endl << "IV: " << (IgnoreIV ? "No" : "Yes");
        if (!IgnoreIV)
            std::cout << std::endl << "IV Length: " << std::to_string(IvLength);

        std::cout << std::endl << "=======================" << std::endl;
    }
    int ICipher::GetCiphertextFixedLength(int& plaintextLength, bool addPadding)
    {
        // If padding is not applied, it just returns the array with length equals to bufferLength
        if (!addPadding)
            return plaintextLength;

        return (plaintextLength - (plaintextLength % BlockSize)) + BlockSize;
    }
    int ICipher::GetFixedCiphertextLengthFromBase64(unsigned char* base64Ciphertext, int& base64CiphertextLength)
    {   
        // Each Base64 digit represents 6 bits
        // If we multiply the length of the base64 buffer by 6,
        // we get the actual number of bits represented by the base64 string.
        // Then, we divide it by 8 and we get the value in bytes.
        // We can now subtract the added padding from the value in bytes and get the
        // actual ciphertext length.
        
        int base64Bytes = (base64CiphertextLength * Horcrux::BASE64_CHAR_BITS) / 8;
        int actualLength = base64Bytes - (base64Bytes % BlockSize);

        return actualLength;
    }
    int ICipher::Encrypt(char* plaintext, int& plaintextLength, unsigned char* outCiphertext)
    {
        return Encrypt(reinterpret_cast<unsigned char*>(plaintext), plaintextLength, outCiphertext);
    }
    int ICipher::Encrypt(unsigned char* plaintext, int& plaintextLength, unsigned char* outCiphertext)
    {
        EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
        
        int len;
        int ciphertextLength;

        if (!context)
            HandleErrors();
        
        if (1 != EVP_EncryptInit_ex(context, GetEvpCipher(), NULL, GetKey(), GetIV()))
            HandleErrors();

        if(1 != EVP_EncryptUpdate(context, outCiphertext, &len, plaintext, plaintextLength))
            HandleErrors();

        ciphertextLength = len;

        if(1 != EVP_EncryptFinal_ex(context, outCiphertext + len, &len))
            HandleErrors();

        ciphertextLength += len;

        EVP_CIPHER_CTX_free(context);

        return ciphertextLength;
    }
    int ICipher::Decrypt(char* ciphertext, int& ciphertextLength, unsigned char* outPlaintext, unsigned char* key, unsigned char* iv)
    {
        return Decrypt(reinterpret_cast<unsigned char*>(ciphertext), ciphertextLength, outPlaintext, key, iv);
    }

    int ICipher::Decrypt(unsigned char* ciphertext, int& ciphertextLength, unsigned char* outPlaintext, unsigned char* key, unsigned char* iv)
    {
        EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
        
        int len;
        int plaintextLength;

        if (!context)
            HandleErrors();
        
        if (1 != EVP_DecryptInit_ex(context, GetEvpCipher(), NULL, key, iv))
            HandleErrors();

        if(1 != EVP_DecryptUpdate(context, outPlaintext, &len, ciphertext, ciphertextLength))
            HandleErrors();

        plaintextLength = len;

        if(1 != EVP_DecryptFinal_ex(context, outPlaintext + len, &len))
        {
            std::cout << "Unable to decrypt. Wrong key?" << std::endl;
            HandleErrors();
        }

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
        Horcrux::PrintErrorAndAbort("Cipher algorithm or mode not supported");
    }

    // ############ Derived Class definitions ############
    AES256::AES256(CIPHER_MODE cipherMode) : ICipher(KEY_LENGTH, IV_LENGTH, BLOCK_SIZE, cipherMode, CIPHER_ALGORITHM::AES_256)
    {

    }
    DataEncryptionStandard::DataEncryptionStandard(CIPHER_MODE cipherMode) : ICipher(KEY_LENGTH, IV_LENGTH, BLOCK_SIZE, cipherMode, CIPHER_ALGORITHM::Data_Encryption_Standard)
    {

    }
}