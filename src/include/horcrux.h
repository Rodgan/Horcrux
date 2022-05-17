#pragma once
#include "cipher.h"
#include "file_manager.h"

namespace Cubbit
{
    class Horcrux{
    public:
        ~Horcrux();
        
        ICipher* Cipher = nullptr;
        IFileManager* FileManager = nullptr;

        static const int BASE64_CHAR_BITS = 6;
        static void PrintErrorAndAbort(const char* error);
        static char* Base64Encode(const char* input, int length);
        static char* Base64Encode(unsigned char* input, int length);
        
        static char* Base64Decode(char * input, int length, int& outDataRead);
        static unsigned char* Base64DecodeAsUnsigned(char * input, int length, int& outDataRead);

        void Encrypt(char* inputFile, int& chunks, char* outputDirectory, char* fileNamePrefix);
        void Decrypt(char** inputFiles, int& numOfFiles, char* outputFile, char* keyInBase64);

    };
}