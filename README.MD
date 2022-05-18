# Horcrux

Horcrux is a CLI based application to encrypt and decrypt your files.
The implementation of new encryption algorithms is fairly simple since Horcrux is based on OpenSSL.
You can save your file locally or implement new features, such as FTP, to save your files on a remote system.

### Installation
You can use **CMAKE** to build the source. I've tested it on both Windows and Linux.

### Encryption Process
```sh
horcrux [options] create -n <horcrux_count> <input_file> <output_path>
```
The parameter *[options]* is *optional* and you can define 2 options:
- **-a** *algorithm name*
    - **AES256** (default)
    - **DES**
- **-m** *algorithm mode of operation*
    - **CBC** (default)
    - **ECB**
- **-p** *file name prefix* (encryption process only)
    
The parameter **horcrux_count** lets you decide how many files you want to split the encrypted file into.
For instance, if you specify **5**, Horcrux will **generate a random key**, encrypt your **input_file**, split the encrypted buffer into **5 chunks** and it will save it in **output_path**.
If the parameter **-p** is not specified, Horcrux will append the number of the chunk to each file (e.g. **voldemort.pdf** becomes **voldemort.pdf_01**, **voldemort.pdf_02** etc...)

The random key will be generated based on the defined algorithm.
If you want to recover your files, you have to define **the same algorithm parameters along with the generated key**.

Note that the file will be named automatically based on how many chunks you want to create.
For instance, if you want to create **9 chunks** with the prefix *"horcrux"*, Horcrux will create **horcrux_1** to **horcrux_9**.
If you want to create **10 chunks**, Horcrux will create **horcrux_01** to **horcrux_10**.
If you want to create **100 chunks**, Horcrux will create **horcrux_001** to **horcrux_100** and so on.
This feature will help the user to load the files in the correct order when decrypting.

### Decryption Process
```sh
horcrux [options] load -k <decryption_key> <input_files> <output_file>
```
The parameter *[options]* is the same as the encryption process.
The parameter **decryption_key** is the generated key (in base64) that Horcrux displayed at the end of the encryption process.
The parameter **input_files** is the list of files that the original file was splitted into.
You can use the wildcard expansion to specify multiple files using a single parameter.
The parameter **output_file** is the full path where you want to save the decrypted file.

### Examples
File to encrypt: *C:\voldemort.pdf*
Output directory: *C:\horcrux\\*
Algorithm: **AES256**
Mode: **CBC**
Chunks: **5**
Prefix: **horcrux**

```sh
horcrux -a AES256 -m CBC create -p "horcrux" -n 5 "C:\voldermort.pdf" "C:\horcrux\"
```
is equivalent to
```sh
horcrux -p "horcrux" create -n 5 "C:\voldermort.pdf" "C:\horcrux"
```

Let's suppose that Horcrux generated the following key:
**RGlkIHlvdSBsaWtlIHRoZSBjb2RlPyBXZWxsLCBJIGNhbiBkbyBiZXR0ZXIgaWYgeW91IGhpcmUgbWUh**

You can decrypt using the following command:
```sh
horcrux load -k "RGlkIHlvdSBsaWtlIHRoZSBjb2RlPyBXZWxsLCBJIGNhbiBkbyBiZXR0ZXIgaWYgeW91IGhpcmUgbWUh" "C:\horcrux\horcrux_*" "C:\voldemort_is_back.pdf"
```

### Implementing new algorithm
In order to implement a new encryption algorithm you have to edit 3 files:
- **cipher.cpp**
- **cipher.h**
- **main.cpp**

Let's try to to implement **AES-128**.
#### cipher.h
First, add the algorithm to the enumerator **CIPHER_ALGORITHM**
```C++
enum CIPHER_ALGORITHM { 
    // ...
    AES_128
};
```
Next, declare the class **AES128** that inherits from **ICipher**.
```C++
class AES128 : public ICipher
{
    // Length is stored in BYTES
    static const int KEY_LENGTH = 128 / 8;
    static const int IV_LENGTH = 128 / 8;
    static const int BLOCK_SIZE = 128 / 8;
public:
    AES128(CIPHER_MODE cipherMode);
};
```
*Note that the base class will ignore the IV if not supported by the selected mode (e.g. ECB).*

#### cipher.cpp
Now, the class definition must be implemented.
In order to do this, just define the class constructor.
```C++
AES128::AES128(CIPHER_MODE cipherMode) : ICipher(KEY_LENGTH, IV_LENGTH, BLOCK_SIZE, cipherMode, CIPHER_ALGORITHM::AES_128) { }
```
Edit the switch constructor in the following method: **GetEvpCipher**. 
```C++
switch(CipherAlgorithm)
{
    // ...
    case CIPHER_ALGORITHM::AES_128:
        if (CipherMode == CIPHER_MODE::CBC) return EVP_aes_128_cbc();
        if (CipherMode == CIPHER_MODE::ECB) return EVP_aes_128_ecb();
    break;
}
```

#### main.cpp
Finally, edit the main.cpp (line ~195)
```C++
if (_algorithmName == "DES")
	horcrux.Cipher = new Cubbit::DataEncryptionStandard(mode);
else if (_algorithmName == "AES128")
	horcrux.Cipher = new Cubbit::AES128(mode);
else
	horcrux.Cipher = new Cubbit::AES256(mode);
```

Cool! Now Horcrux supports AES-128!