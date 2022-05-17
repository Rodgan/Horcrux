#include "horcrux.h"
#include "cipher.h"
#include "file_manager.h"

#include <iostream>
#include <string>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

const int MINIMUM_CONSOLE_ARGUMENTS = 6;
void ShowHelpAndAbort()
{
	std::cout << std::endl << "=====FILE ENCRYPTION=====" << std::endl;
	std::cout << "horcrux [options] create -n <horcrux_count> <input_file> <output_path>" << std::endl;
	std::cout << "horcrux_count:\t\tnumber of encrypted files (chunks) that will be generated" << std::endl;
	std::cout << "input_file:\t\tthe file you want to encrypt" << std::endl;
	std::cout << "output_path:\t\tthe path you want your file(s) to be generated" << std::endl << std::endl;
	
	std::cout << "=====FILE DECRYPTION=====" << std::endl;
	std::cout << "horcrux [options] load -k <base64_key> <input_files> <output_file>" << std::endl;
	std::cout << "base64_key:\t\tthe key generated during the encryption process" << std::endl;
	std::cout << "input_files:\t\tthe file(s) generated during the encryption process" << std::endl;
	std::cout << "output_file:\t\tthe full path where you want to save your decrypted file" << std::endl << std::endl;

	std::cout << "=====OPTIONS=====" << std::endl;
	std::cout << "You can specify the algorithm used to encrypt or decrypt your files." << std::endl;
	std::cout << "Available options:" << std::endl;
	std::cout << " -a\t\tEncryption algorithm" << std::endl;
	std::cout << "\t\tAES256,DES (default: AES256)" << std::endl;
	std::cout << " -m\t\tMode of operation" << std::endl;
	std::cout << "\t\tCBC,ECB (default: CBC)" << std::endl;
	std::cout << " -p\t\tPrefix of each chunk (encryption process only)" << std::endl;
	std::cout << "\t\te.g \"horcrux\"" << std::endl << std::endl;

	#ifdef _WIN32
	std::cout << "=====EXAMPLES=====" << std::endl;
	std::cout << "horcrux -a AES256 -m CBC create -p \"horcrux\" -n 2 \"C:\\voldemort.pdf\" \"C:\\horcrux\\\"" << std::endl;
	std::cout << "horcrux -a AES256 -m CBC load -k \"<base64_key>\" \"C:\\horcrux\\horcrux_1\" \"C:\\horcrux\\horcrux_2\" \"C:\\voldemort_is_back.pdf\"" << std::endl;
	std::cout << "or, using the wildcard expansion:" << std::endl;
	std::cout << "horcrux -a AES256 -m CBC load -k \"<base64_key>\" \"C:\\horcrux\\horcrux_*\" \"C:\\voldemort_is_back.pdf\"" << std::endl << std::endl;
	std::cout << "Please, remember that during the decryption process you need to specify the same parameters you set during the encryption process." << std::endl << std::endl;
	#else
	std::cout << "=====EXAMPLES=====" << std::endl;
	std::cout << "horcrux -a AES256 -m CBC create -p \"horcrux\" -n 2 \"~/Desktop/voldemort.pdf\" \"~/Desktop/horcrux/\"" << std::endl;
	std::cout << "horcrux -a AES256 -m CBC load -k \"<base64_key>\" \"~/Desktop/horcrux/horcrux_1\" \"~/Desktop/horcrux/horcrux_1\" \"~/Desktop/voldemort_is_back.pdf\"" << std::endl;
	std::cout << "or, using the wildcard expansion:" << std::endl;
	std::cout << "horcrux -a AES256 -m CBC load -k \"<base64_key>\" \"~/Desktop/horcrux/horcrux_*\" \"~/Desktop/voldemort_is_back.pdf\"" << std::endl << std::endl;
	std::cout << "Please, remember that during the decryption process you need to specify the same parameters you set during the encryption process." << std::endl << std::endl;
	#endif

	abort();
}

const char* ARGUMENT_ENCRYPTION_ALGORITHM = "-a";
const char* ARGUMENT_ENCRYPTION_MODE = "-m";
const char* ARGUMENT_FILE_NAME_PREFIX = "-p";

const char* ARGUMENT_ENCRYPT_PROCESS = "create";
const char* ARGUMENT_HORCRUX_COUNT = "-n";

const char* ARGUMENTY_DECRYPT_PROCESS = "load";
const char* ARGUMENT_DECRYPTION_KEY = "-k";

int main(int argc, char** argv)
{
	if (argc < MINIMUM_CONSOLE_ARGUMENTS)
		ShowHelpAndAbort();

	bool fileNamePrefixcSpecified = false;
	bool algorithmSpecified = false;
	bool algorithmModeSpecified = false;
	bool processTypeSelected = false; // encryption or decryption
	bool encrypt = false;
	bool decrypt = false;

	char* algorithmName = nullptr;
	char* algorithmMode = nullptr;
	char* fileNamePrefix = nullptr;
	char* inputFile = nullptr;
	char** inputFiles = nullptr; // can be used for encryption (1 file) and decryption (n files)
	char* output = nullptr; // can be used for encryption (directory) and decryption (full path)
	char* horcruxCount = nullptr;
	char* key = nullptr;

	int inputFilesCount = 0;
	for (int i = 1; i < argc; i++)
	{
		std::string argument = argv[i];
		char* w = argv[i];

		if (!algorithmSpecified || !algorithmModeSpecified || !fileNamePrefixcSpecified)
		{
			if (argument.compare(ARGUMENT_ENCRYPTION_ALGORITHM) == 0 && algorithmSpecified)
				ShowHelpAndAbort();
			
			if (argument.compare(ARGUMENT_ENCRYPTION_ALGORITHM) == 0 && !algorithmSpecified && i < argc - 6) // after "-a" we need at least 6 more arguments
			{
				algorithmSpecified = true;
				algorithmName = argv[i + 1];
				i++;
				continue;
			}

			if (argument.compare(ARGUMENT_ENCRYPTION_MODE) == 0 && algorithmModeSpecified)
				ShowHelpAndAbort();
			
			if (argument.compare(ARGUMENT_ENCRYPTION_MODE) == 0 && !algorithmModeSpecified && i < argc - 6) // after "-m" we need at least 6 more arguments
			{
				algorithmModeSpecified = true;
				algorithmMode = argv[i + 1];
				i++;
				continue;
			}

			if (argument.compare(ARGUMENT_FILE_NAME_PREFIX) == 0 && fileNamePrefixcSpecified)
				ShowHelpAndAbort();

			if (argument.compare(ARGUMENT_FILE_NAME_PREFIX) == 0 && !fileNamePrefixcSpecified && i < argc - 6) // after "-p" we need at least 6 more arguments
			{
				fileNamePrefixcSpecified = true;
				fileNamePrefix = argv[i + 1];
				i++;
				continue;
			}
		}


		if (argument.compare(ARGUMENT_ENCRYPT_PROCESS) == 0 && i < argc - 4) // after "create" we need at least 4 more arguments
		{
			std::string nextArgument = argv[i + 1];

			if (nextArgument.compare(ARGUMENT_HORCRUX_COUNT) == 0)
			{
				horcruxCount = argv[i + 2];
				inputFile = argv[i + 3];
				output = argv[i + 4];
				inputFilesCount = 1;
				processTypeSelected = true;
				encrypt = true;
				break;
			}
		}

		if (argument.compare(ARGUMENTY_DECRYPT_PROCESS) == 0 && i < argc - 4) // after "load" we need at least 4 more arguments
		{
			// Argument not supported in decryption process
			if (fileNamePrefixcSpecified)
				ShowHelpAndAbort();

			std::string nextArgument = argv[i + 1];
			
			if (nextArgument.compare(ARGUMENT_DECRYPTION_KEY) == 0)
			{
				key = argv[i + 2];

				int bufferLength = 0;
				inputFilesCount = (argc - 1) - (i+3);

				inputFiles = new char*[inputFilesCount];
				
				for (int j = 0; j < inputFilesCount; j++)
				{
					inputFiles[j] = new char[strlen(argv[j + i + 3])];
					inputFiles[j] = argv[j + i + 3];
				}

				output = argv[argc - 1];
				decrypt = true;
				processTypeSelected = true;
				break;
			}
		}	
	}

	if (!processTypeSelected)
		ShowHelpAndAbort();
		
	std::string _algorithmMode = algorithmMode ? std::string(algorithmMode) : "CBC"; 
	std::string _algorithmName = algorithmName ? std::string(algorithmName) : "AES256";

	Cubbit::Horcrux horcrux;
	Cubbit::LocalDisk fileManager;
	Cubbit::CIPHER_MODE mode;
	
	if (_algorithmMode == "ECB")
		mode = Cubbit::CIPHER_MODE::ECB;
	else
		mode = Cubbit::CIPHER_MODE::CBC;

	horcrux.FileManager = &fileManager;
	
	if (_algorithmName == "DES")
		horcrux.Cipher = new Cubbit::DataEncryptionStandard(mode);
	else
		horcrux.Cipher = new Cubbit::AES256(mode);

	if (encrypt)
	{
		int chunks = std::stoi(std::string(horcruxCount));
		horcrux.Encrypt(inputFile, chunks, output, fileNamePrefix);
	}
	else if (decrypt)
	{
		horcrux.Decrypt(inputFiles, inputFilesCount, output, key);
		delete[] inputFiles;
	}
	
	
	return 0;
}