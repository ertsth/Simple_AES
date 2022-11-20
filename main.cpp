#include "src/AES.hpp"
#include <string>
#include <iostream>

int main(int argc, char *argv[])
{
    std::string plaintext = "The Advanced Encryption Standard (AES), also known by its original name Rijndael, is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001";
    std::string key =   "Bdi6L0oAx0UpaKlk";

    AES aes(AESKey::AES_128);

    std::vector<unsigned char> plaintext_v(plaintext.begin(), plaintext.end());
    std::vector<unsigned char> key_v(key.begin(), key.end());

    std::cout << "Original text: " << std::endl;
    for (auto ch : plaintext_v) {
        std::cout << ch;
    }
    std::cout << std::endl;

    std::vector<unsigned char> result = aes.encrypt(plaintext_v, key_v);

    std::cout << "Encrypted text: " << std::endl;
    for (auto ch : result) {
        std::cout << std::hex << (int) ch << " ";
    }
    std::cout << std::dec << std::endl;

    std::vector<unsigned char> deresult = aes.decrypt(result, key_v);

    std::cout << "Decrypted text: " << std::endl;
    for (auto ch : deresult) {
        std::cout << ch;
    }
    std::cout << std::endl;

    return 0;
}