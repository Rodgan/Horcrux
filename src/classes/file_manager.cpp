#include "horcrux.h"
#include "file_manager.h"
#include "cipher.h"
#include <iostream>
#include <limits>
#include <fstream>
#include <string>


void LocalDisk::EncryptFileAndSave(char* inputFile, int& chunks, char* fileNamePrefix, char* outputDirectory, ICipher& cipher)
{
    std::ifstream file;

    file.open(inputFile, std::ios::in | std::ios::binary);

    if (!file.is_open())
        Horcrux::PrintErrorAndAbort("Unable to open the file (EncryptFile)");

    file.ignore(std::numeric_limits<std::streamsize>::max());
    std::streamsize length = file.gcount();
    file.clear();
    file.seekg(0, std::ios_base::beg);

    char* buffer = new char[length];
    file.read(buffer, length);
    file.close();

    int bufferLength = (int) length;
    unsigned char* ciphertext = new unsigned char[bufferLength];
    int ciphertextLength = cipher.Encrypt(buffer, bufferLength, ciphertext);
    SaveEncryptedFile(ciphertext, ciphertextLength, chunks, fileNamePrefix, outputDirectory);

    // delete[] ciphertext; // not working uhm...
}
void LocalDisk::SaveEncryptedFile(unsigned char* ciphertext, int& ciphertextLength, int& chunks, char* fileNamePrefix, char* outputDirectory)
{
    // Standard split
    // Divide each chunk in N bytes (ciphertextLength / chunks)
    // Using the modulo operator, calculate the size of the last chunk

    // e.g.
    // File size: 100
    // Chunks: 9
    // Size of each chunk: 100 / 9 = 11
    // Size of last chunk: 11 + (100 % 9) = 11 + 1 = 12
    // So we have 8 chunks of 11 and 1 chunk of 12
    // Result: (8 * 11) + 12 = 100
    int chunkSize = ciphertextLength / chunks;
    int lastChunkSize = chunkSize + (ciphertextLength % chunks);

    for (int i = 0; i < chunks; i++)
    {
        std::string fileName = std::string(outputDirectory) + std::string(fileNamePrefix) + std::string("_") + std::to_string(i);

        int sizeOfCurrentChunk = (i == chunks - 1) ? lastChunkSize : chunkSize;
        unsigned char* chunk = ciphertext + (chunkSize * i);

        std::ofstream file;
        file.open(fileName, std::ios::out | std::ios::binary);

        if (!file.is_open())
            Horcrux::PrintErrorAndAbort("Unable to open the file (SaveEncryptedFile)");

        file.write((const char*) chunk, sizeOfCurrentChunk);

        file.clear();
        file.close();
    }
}
void LocalDisk::DecryptFilesAndSave(char** files, int numOfFiles, ICipher& cipher, char* outputFile)
{
    FileSize* fileSize = new FileSize[numOfFiles];
    int ciphertextLength = GetFinalDecryptedFileBufferSize(files, numOfFiles, fileSize);
    char* ciphertext = new char[ciphertextLength];
 

    int offset = 0;
    for (int i = 0; i < numOfFiles; i++)
    {
        char* currentFile = fileSize[i].File;

        std::ifstream file;

        file.open(currentFile, std::ios::in | std::ios::binary);

        if (!file.is_open())
            Horcrux::PrintErrorAndAbort("Unable to open the file (DecryptFiles - ifstream)");

        int size = fileSize[i].Size;

        file.read(ciphertext + offset, size);
        file.clear();
        file.close();

        offset += size;
    }

    unsigned char* plaintext = new unsigned char[ciphertextLength];

    int plaintextLength = cipher.Decrypt(ciphertext, ciphertextLength, plaintext, cipher.GetKey(), cipher.GetIV());

    std::ofstream file;

    file.open(outputFile, std::ios::out | std::ios::binary);

    if (!file.is_open())
        Horcrux::PrintErrorAndAbort("Unable to open the file (DecryptFiles - ofstream)");

    file.write(reinterpret_cast<char*>(plaintext), plaintextLength);
    file.clear();
    file.close();

    delete[] fileSize;
    delete[] ciphertext;
    delete[] plaintext;
}
int LocalDisk::GetFinalDecryptedFileBufferSize(char** files, int numOfFiles, FileSize* outFileSize)
{
    int size = 0;

    for (int i = 0; i < numOfFiles; i++)
    {
        char* currentFile = files[i];
        std::ifstream file;

        file.open(currentFile, std::ios::in | std::ios::binary);

        if (!file.is_open())
            Horcrux::PrintErrorAndAbort("Unable to open the file (GetFinalDecryptedFileBufferSize)");

        file.ignore(std::numeric_limits<std::streamsize>::max());
        int currentFileSize = file.gcount();
        size += currentFileSize;
        file.clear();
        file.close();

        outFileSize[i].File = currentFile;
        outFileSize[i].Size = currentFileSize;
    }

    return size;
}

