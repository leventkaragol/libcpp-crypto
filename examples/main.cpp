#include "libcpp-crypto.hpp"

using namespace lklibs;

void encryptWithAES()
{
    auto plainText = "This text will be encrypted soon";
    auto key = "mySecretKey";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);

    std::cout << "Encrypted Text: " << encryptedText << std::endl;
}

void decryptWithAES()
{
    auto encryptedText = "D9ktQq1ZnV32JXr5YUpSJcTegqrfCHFi7aDNPGgrtsRmYLqS5YLGBKemqUwPzEeYLVN6ww4hL6ZptcZBLktbhg==";
    auto key = "mySecretKey";

    auto plainText = CryptoService::decryptWithAES(encryptedText, key);

    std::cout << "Decrypted Text: " << plainText << std::endl;
}

void invalidKeyExceptionWithAES()
{
    auto encryptedText = "D9ktQq1ZnV32JXr5YUpSJcTegqrfCHFi7aDNPGgrtsRmYLqS5YLGBKemqUwPzEeYLVN6ww4hL6ZptcZBLktbhg==";
    auto key = "myInvalidKey";

    try
    {
        auto plainText = CryptoService::decryptWithAES(encryptedText, key);
    }
    catch (const InvalidKeyException& e)
    {
        std::cout << "Decryption Error: " << e.what() << std::endl;
    }
}

void CorruptedTextExceptionWithAES()
{
    auto encryptedText = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    auto key = "mySecretKey";

    try
    {
        auto plainText = CryptoService::decryptWithAES(encryptedText, key);
    }
    catch (const CorruptedTextException& e)
    {
        std::cout << "Decryption Error: " << e.what() << std::endl;
    }
}

int main()
{
    encryptWithAES();

    decryptWithAES();

    invalidKeyExceptionWithAES();

    CorruptedTextExceptionWithAES();

    return 0;
}
