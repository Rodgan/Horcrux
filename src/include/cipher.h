#pragma once
#include <openssl/evp.h>


enum CIPHER_MODE 
{
    CBC = 0, // Cipher block chaining <- safer than ECB
    // you can add more elements but you need to implement them
};
enum CIPHER_ALGORITHM
{
    AES_256
     // you can add more elements but you need to implement them
};

// Base class for ciphers
class ICipher
{
protected:
    // Key length in bytes
    // It must be set in the derived class before calling GenerateRandomKey();
    int KeyLength = -1; 
    int IvLength = -1;
    CIPHER_MODE CipherMode;
    CIPHER_ALGORITHM CipherAlgorithm;
public:
    // Key + IV
    // It should be more efficient than storing them in different locations
    unsigned char* Key = nullptr;
    
    ICipher(int keyLength, int ivLength, CIPHER_MODE cipherMode, CIPHER_ALGORITHM cipherAlgorithm);
    ~ICipher();
    
    // Generate N (KeyLength) random bytes. Used during encryption process
    void GenerateRandomKey();
    // Set key for decryption process. The key length is defined in the derived class.
    void SetKey(unsigned char* key);
    // Returns a pointer to the key
    unsigned char* GetKey();
    // Returns a pointer to the IV
    unsigned char* GetIV();
    // Get Key Length
    int& GetKeyLength();
    // Get IV Length
    int& GetIVLength();
    
    const EVP_CIPHER* GetEvpCipher();
    void HandleErrors();

    virtual unsigned char* Encrypt(unsigned char* buffer, int bufferLength, int* outCiphertextLength);
    virtual void Decrypt(char* buffer);
};

// Check https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
class Aes256 : public ICipher
{
    static const int KEY_LENGTH = 32; // 256 bit
    static const int IV_LENGTH = 16; // 128 bit
public:
    Aes256(CIPHER_MODE cipherMode);
    
    void Decrypt(char* buffer);
};