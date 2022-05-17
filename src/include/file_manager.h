#pragma once
#include "cipher.h"
#include <string>
#include <iostream>

namespace Cubbit
{
    struct FileSize
    {
        int Size;
        char* File;
    };

    class IFileManager
    {
    protected:
        #ifdef _WIN32
        const char slash = '\\';
        #else
        const char slash = '/';
        #endif
        char* AddSlashToDirectory(char* outputDirectory, bool& needToBeDeleted);
        char* FixChunkNumber(int chunkNumber, int& maxNumOfChunks);
        virtual void SaveEncryptedFile(unsigned char* ciphertext, int& ciphertextLength, int& chunks, char* fileNamePrefix, char* outputDirectory) = 0;
        virtual int GetFinalDecryptedFileBufferSize(char** files, int numOfFiles, FileSize* outFileSize) = 0;
    public:
        virtual void EncryptFileAndSave(char* inputFile, int& chunks, char* fileNamePrefix, char* outputDirectory, ICipher& cipher) = 0;
        virtual void DecryptFilesAndSave(char** files, int numOfFiles, ICipher& cipher, char* outputFile) = 0;
    };

    class LocalDisk : public IFileManager
    {
    protected:
        virtual int GetFinalDecryptedFileBufferSize(char** files, int numOfFiles, FileSize* outFileSize);
        virtual void SaveEncryptedFile(unsigned char* ciphertext, int& ciphertextLength, int& chunks, char* fileNamePrefix, char* outputDirectory);
    public:
        virtual void EncryptFileAndSave(char* inputFile, int& chunks, char* fileNamePrefix, char* outputDirectory, ICipher& cipher);
        virtual void DecryptFilesAndSave(char** files, int numOfFiles, ICipher& cipher, char* outputFile);
    };
}