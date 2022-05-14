#pragma once

enum CIPHER_MODE 
{
    CBC = 0, // Cipher block chaining <- safer
    ECB = 1 // Electronic code book <- not safe
    // you can add more elements but you need to implement them
};
enum CIPHER_ALGORITHM
{
    AES_256
};

// Base class for ciphers
class ICipher
{
protected:
    // Key length in bytes
    // It must be set in the derived class before calling GenerateRandomKey();
    int KeyLength = -1; 
    CIPHER_MODE CipherMode;
    CIPHER_ALGORITHM CipherAlgorithm;

public:
    // Key
    // It must be initialized in the derived class
    // e.g. Key = new unsigned char[KEY_LENGTH];
    unsigned char* Key = nullptr;
    
    ICipher(int keyLength, CIPHER_MODE cipherMode, CIPHER_ALGORITHM cipherAlgorithm);
    ~ICipher();
    
    // Generate N (KeyLength) random bytes. Used during encryption process
    void GenerateRandomKey();
    // Set key for decryption process
    void SetKey(unsigned char* key, int keyLength);
    // Get Key Length (key + iv)
    int& GetKeyLength();

    void HandleErrors();

    virtual void Encrypt(char* buffer) = 0;
    virtual void Decrypt(char* buffer) = 0;
};

// Check https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
class Aes256 : public ICipher
{
    static const int KEY_LENGTH = 32; // 256 bit
    static const int IV_LENGTH = 16; // 128 bit
    static const int BLOCK_SIZE_IN_BIT = 128; // 128 bit
public:
    Aes256(CIPHER_MODE cipherMode = CIPHER_MODE::CBC);

    void Encrypt(char* buffer);
    void Decrypt(char* buffer);
};