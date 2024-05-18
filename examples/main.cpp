#include "libcpp-crypto.hpp"

using namespace lklibs;

void encrypt()
{
    std::string input = "Hello, World!";
    std::string key = "asdqwerty123asd1234safd324dfdsdf";

    auto encrypted = CryptoService::encryptWithAES(input, key);
    auto decrypted = CryptoService::decryptWithAES(encrypted, key);

    std::cout << "Encrypted: " << encrypted << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
}

int main()
{
    encrypt();

    return 0;
}
