#pragma once
#include <openssl/evp.h>

namespace Cubbit
{
    enum CIPHER_MODE 
    {
        CBC, // Cipher block chaining <- safer
        ECB // Electronic Code Book
        // you can add more elements but you need to implement them
    };
    enum CIPHER_ALGORITHM
    {
        AES_256,
        Data_Encryption_Standard // Just wanted to show that we can implement ciphers easily. Please, do not use DES.
        // you can add more elements but you need to implement them
    };

    // Base class for ciphers
    class ICipher
    {
    protected:
        // Length is stored in bytes
        // It must be set in the derived class before calling GenerateRandomKey();
        int KeyLength = -1; 
        int IvLength = -1;
        int BlockSize = -1;

        bool IgnoreIV = false; // In some cipher mode IV is not necessary
        CIPHER_MODE CipherMode;
        CIPHER_ALGORITHM CipherAlgorithm;
    public:
        // Key and IV are stored together.
        // It should be more efficient than storing them in different locations
        // You can retrieve the Key and the IV pointers using the GetKey() and GetIV() methods.
        // Remember that Key and IV are NOT strings, so you have to use GetKeyLength() and GetIVLength()
        // in order to get the actual Key and IV length.
        unsigned char* Key = nullptr;
        
        ICipher(int keyLength, int ivLength, int blockSize, CIPHER_MODE cipherMode, CIPHER_ALGORITHM cipherAlgorithm);
        ~ICipher();
        
        // Generate N (KeyLength) random bytes. Used during encryption process
        void GenerateRandomKey();
        // Set Key and IV by specifying a single buffer
        void SetKeyAndIVFromBase64String(char* buffer, int bufferLength);
        // Returns a pointer to the key
        unsigned char* GetKey();
        // Returns a pointer to the IV
        unsigned char* GetIV();
        // Get Key Length
        int& GetKeyLength();
        // Get IV Length
        int& GetIVLength();
        // Just a wrapper. You can do it using GetKey() and GetKeyLength() + GetIVLEngth();
        unsigned char* GetFullKeyAndIv(int& outTotalLength);

        // Get the actual length of the cipher text (before encrption)
        int GetCiphertextFixedLength(int& plaintextLength, bool addPadding);
        // Get the actual length of the cipher text (before decryption)
        int GetFixedCiphertextLengthFromBase64(unsigned char* base64Ciphertext, int& base64CiphertextLength);

        // Display the algorithm informations to the user
        void DisplayAlgorithmInfo();

        void HandleErrors();

        virtual int Encrypt(char* plaintext, int& plaintextLength, unsigned char* outCiphertext);
        virtual int Encrypt(unsigned char* plaintext, int& plaintextLength, unsigned char* outCiphertext);
        virtual int Decrypt(unsigned char* ciphertext, int& ciphertextLength, unsigned char* outPlaintext, unsigned char* key, unsigned char* iv);
        virtual int Decrypt(char* ciphertext, int& ciphertextLength, unsigned char* outPlaintext, unsigned char* key, unsigned char* iv);
        const EVP_CIPHER* GetEvpCipher();
    };

    // Check https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
    class AES256 : public ICipher
    {
        // Length is stored in BYTES
        static const int KEY_LENGTH = 256 / 8;
        static const int IV_LENGTH = 128 / 8;
        static const int BLOCK_SIZE = 128 / 8;
    public:
        AES256(CIPHER_MODE cipherMode);
    };

    class DataEncryptionStandard : public ICipher
    {
        // Length is stored in BYTES
        static const int KEY_LENGTH = 64 / 8;
        static const int IV_LENGTH = 128 / 8;
        static const int BLOCK_SIZE = 64 / 8;
    public:
        DataEncryptionStandard(CIPHER_MODE cipherMode);
    };
}