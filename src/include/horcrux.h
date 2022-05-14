#pragma once

class Horcrux{
public:
    void Encrypt();
    void Dencrypt();
    char* Base64Encode(const char* input, int length);
    char* Base64Encode(unsigned char* input, int length);
    
    char* Base64Decode(char * input, int length);
};