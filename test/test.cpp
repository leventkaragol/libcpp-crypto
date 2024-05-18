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

TEST(DecryptWithAESTest, DecryptionWithAESMustBeCompletedSuccessfullyForSpecialCharsWithAValidKey)
{
    std::string plainText = "Test message to be used during tests with special characters: !@#$%^&*()_+{}|:<>?~`-=[]\\;',./öçşığüÖÇŞİĞÜ";
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

    try
    {
        CryptoService::decryptWithAES(encryptedText, invalidKey);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const InvalidKeyException& e)
    {
        EXPECT_EQ(std::string(e.what()), "Encryption key does not match the original encryption key");
    }
    catch (...)
    {
        FAIL() << "Expected std::runtime_error";
    }
}

TEST(DecryptWithAESTest, DecryptionWithAESMustBeFailedWithAnInvalidEncryptedText)
{
    auto encryptedText = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    std::string key = "mySecretKey";

    try
    {
        CryptoService::decryptWithAES(encryptedText, key);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const CorruptedTextException& e)
    {
        EXPECT_EQ(std::string(e.what()), "Encrypted text is corrupted");
    }
    catch (...)
    {
        FAIL() << "Expected std::runtime_error";
    }
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
