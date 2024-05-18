#include "libcpp-crypto.hpp"
#include <gtest/gtest.h>

using namespace lklibs;

TEST(EncryptWithAESTest, EncryptionWithAESMustBeCompletedSuccessfullyWithAValidKey)
{
    std::string plainText = "Test message to be used during tests";
    std::string key = "mySecretKey";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);

    ASSERT_FALSE(encryptedText.empty()) << "encryptedText is empty";
}

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
