#pragma once
#include "cipher.h"
#include <string>
#include <iostream>
struct FileSize
{
    int Size;
    char* File;
};

class IFileManager
{
public:
    void PrintErrorAndAbort(std::string error);
    // virtual bool FileExists() = 0;
    // virtual bool FilesExist() = 0;

    // virtual void ReadFile() = 0;

    virtual void EncryptFile(char* inputFile, int& chunks, char* fileNamePrefix, char* outputDirectory, ICipher& cipher) = 0;
    virtual void SaveEncryptedFile(unsigned char* ciphertext, int& ciphertextLength, int& chunks, char* fileNamePrefix, char* outputDirectory) = 0;
    virtual int GetFinalDecryptedFileBufferSize(char** files, int numOfFiles, FileSize* outFileSize) = 0;
    virtual void DecryptFilesAndSave(char** files, int numOfFiles, ICipher& cipher, char* outputFile) = 0;
    // virtual void WriteFile() = 0;
    // virtual void WriteFiles() = 0;
};

class LocalDisk : public IFileManager
{
public:

    void EncryptFile(char* inputFile, int& chunks, char* fileNamePrefix, char* outputDirectory, ICipher& cipher);
    int GetFinalDecryptedFileBufferSize(char** files, int numOfFiles, FileSize* outFileSize);
    void DecryptFilesAndSave(char** files, int numOfFiles, ICipher& cipher, char* outputFile);
    // You can override this method if you want to change the way the application splits the file
    virtual void SaveEncryptedFile(unsigned char* ciphertext, int& ciphertextLength, int& chunks, char* fileNamePrefix, char* outputDirectory);

};