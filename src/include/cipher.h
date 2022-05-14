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
    // Length is stored in bytes
    // It must be set in the derived class before calling GenerateRandomKey();
    int KeyLength = -1; 
    int IvLength = -1;
    int BlockSize = -1;

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
    void SetKeyAndIV(unsigned char* buffer);
    // Returns a pointer to the key
    unsigned char* GetKey();
    // Returns a pointer to the IV
    unsigned char* GetIV();
    // Get Key Length
    int& GetKeyLength();
    // Get IV Length
    int& GetIVLength();
    // Prepare the ciphertext pointer
    int GetCiphertextFixedLength(int& plaintextLength, bool addPadding);
    int GetFixedCiphertextLengthFromBase64(unsigned char* base64Ciphertext, int& base64CiphertextLength);

    const EVP_CIPHER* GetEvpCipher();
    void HandleErrors();

    virtual int Encrypt(unsigned char* plaintext, int& plaintextLength, unsigned char* ciphertext);
    virtual int Decrypt(unsigned char* cipertext, int& cipertextLength, unsigned char* plaintext, unsigned char* key, unsigned char* iv);
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