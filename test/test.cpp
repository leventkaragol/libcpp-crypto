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

TEST(DecryptWithAESTest, DecryptionWithAESMustBeCompletedSuccessfullyWithAValidKey)
{
    std::string plainText = "Test message to be used during tests";
    std::string key = "mySecretKey";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(DecryptWithAESTest, DecryptionWithAESMustBeFailedWithAnInvalidKey)
{
    std::string plainText = "Test message to be used during tests";
    std::string key = "mySecretKey";
    std::string invalidKey = "invalidKey";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, invalidKey);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(AESKeyTest, AESEncryptionShouldBePossibleWithAKeyLessThan32Characters)
{
    std::string plainText = "Test message to be used during tests";
    std::string key = "123";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(AESKeyTest, AESEncryptionShouldBePossibleWithAKeyLargerThan32Characters)
{
    std::string plainText = "Test message to be used during tests";
    std::string key = "abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_+{}|:<>?~`-=[]\\;',./";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(AESKeyTest, AESEncryptionShouldBePossibleWithA32CharactersKey)
{
    std::string plainText = "Test message to be used during tests";
    std::string key = "abcdefghijklmnopqrstuvwxyz123456";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(AESKeyTest, AESEncryptionMustBePossibleWithAKeyContainingSpecialCharacters)
{
    std::string plainText = "Test message to be used during tests";
    std::string key = "!@#$%^&*()_+{}|:<>?~`-=[]\\;',./";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
