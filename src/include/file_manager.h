#pragma once

class IFileManager
{
public:
    virtual bool CanReadFile() = 0;
    
    // virtual bool CanWrite() = 0;

    // virtual bool FileExists() = 0;
    // virtual bool FilesExist() = 0;

    // virtual void ReadFile() = 0;
    // virtual void ReadFiles() = 0;
    
    // virtual void WriteFile() = 0;
    // virtual void WriteFiles() = 0;
};

class LocalDisk : public IFileManager
{
public:
    bool CanReadFile();
};