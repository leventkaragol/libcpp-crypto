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

        FAIL() << "Expected InvalidKeyException";
    }
    catch (const InvalidKeyException& e)
    {
        EXPECT_EQ(std::string(e.what()), "Encryption key does not match the original encryption key");
    }
    catch (...)
    {
        FAIL() << "Expected InvalidKeyException";
    }
}

TEST(DecryptWithAESTest, DecryptionWithAESMustBeFailedWithAnCorruptedEncryptedText)
{
    auto encryptedText = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    std::string key = "mySecretKey";

    try
    {
        CryptoService::decryptWithAES(encryptedText, key);

        FAIL() << "Expected CorruptedTextException";
    }
    catch (const CorruptedTextException& e)
    {
        EXPECT_EQ(std::string(e.what()), "Encrypted text is corrupted");
    }
    catch (...)
    {
        FAIL() << "Expected CorruptedTextException";
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

TEST(EncryptWithRSATest, EncryptionWithRSAMustBeCompletedSuccessfullyWithAValidPublicKey)
{
    auto plainText = "This text will be encrypted soon";

    auto publicKey = "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIASR0gIwizgv0j/Gzj6\n"
        "E/gS1J6gwUXeDBND7c4rDdqh/NP78N6pWNKxa5YAytTAOsoqxLDRL29pq55HyRw5\n"
        "47M35hwdmEfE8bOjnogvHRRKu7A2iGV7akkK0cP6XgHgcJVlXBX2xCT70nIX4dDk\n"
        "vGhSKwrps1o+3XVhtnVoPsCDQEESApGalhQ55OT8s0fM7OTFMfqsV3GD9J9FO4wP\n"
        "BlawHpQ5rbWGsyNYXnjXzGpmuyKl4xQBVdbx1tzh+1XlwqMhbXibMozo5U5De0oH\n"
        "A9z1Owbt3++3t+LykQDcHEtiKcvYt71by1X3J2IQOBAwWJ2jRjZQ5QJWaGXirPdR\n"
        "VwIDAQAB\n"
        "-----END PUBLIC KEY-----";

    auto encryptedText = CryptoService::encryptWithRSA(plainText, publicKey);

    ASSERT_FALSE(encryptedText.empty()) << "encryptedText is empty";
}

TEST(EncryptWithRSATest, EncryptionWithRSAMustBeFailedWithAnInvalidPublicKey)
{
    auto plainText = "This text will be encrypted soon";

    auto publicKey = "-----BEGIN PUBLIC KEY-----\n"
        "SOME_INVALID_KEY\n"
        "-----END PUBLIC KEY-----";

    try
    {
        auto encryptedText = CryptoService::encryptWithRSA(plainText, publicKey);

        FAIL() << "Expected InvalidPublicKeyException";
    }
    catch (const InvalidPublicKeyException& e)
    {
        EXPECT_EQ(std::string(e.what()), "RSA public key is invalid");
    }
    catch (...)
    {
        FAIL() << "Expected InvalidPublicKeyException";
    }
}

TEST(EncryptWithRSATest, EncryptionWithRSAMustBeFailedWithTooLongText)
{
    auto plainText = "This text used for testing is too long as a 2048 bit key is used during encryption with RSA, so it will give an exception. The longest text that can be encrypted with a 2048 bit key is 245 characters. However there are 246 characters in this text";

    auto publicKey = "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIASR0gIwizgv0j/Gzj6\n"
        "E/gS1J6gwUXeDBND7c4rDdqh/NP78N6pWNKxa5YAytTAOsoqxLDRL29pq55HyRw5\n"
        "47M35hwdmEfE8bOjnogvHRRKu7A2iGV7akkK0cP6XgHgcJVlXBX2xCT70nIX4dDk\n"
        "vGhSKwrps1o+3XVhtnVoPsCDQEESApGalhQ55OT8s0fM7OTFMfqsV3GD9J9FO4wP\n"
        "BlawHpQ5rbWGsyNYXnjXzGpmuyKl4xQBVdbx1tzh+1XlwqMhbXibMozo5U5De0oH\n"
        "A9z1Owbt3++3t+LykQDcHEtiKcvYt71by1X3J2IQOBAwWJ2jRjZQ5QJWaGXirPdR\n"
        "VwIDAQAB\n"
        "-----END PUBLIC KEY-----";

    try
    {
        auto encryptedText = CryptoService::encryptWithRSA(plainText, publicKey);

        FAIL() << "Expected TextTooLongForPublicKeyException";
    }
    catch (const TextTooLongForPublicKeyException& e)
    {
        EXPECT_EQ(std::string(e.what()), "The text to be encrypted is too long for the public key used");
    }
    catch (...)
    {
        FAIL() << "Expected TextTooLongForPublicKeyException";
    }
}

TEST(DecryptWithRSATest, DecryptionWithRSAMustBeCompletedSuccessfullyWithAValidPrivateKey)
{
    auto plainText = "This text will be encrypted soon";

    auto publicKey = "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIASR0gIwizgv0j/Gzj6\n"
        "E/gS1J6gwUXeDBND7c4rDdqh/NP78N6pWNKxa5YAytTAOsoqxLDRL29pq55HyRw5\n"
        "47M35hwdmEfE8bOjnogvHRRKu7A2iGV7akkK0cP6XgHgcJVlXBX2xCT70nIX4dDk\n"
        "vGhSKwrps1o+3XVhtnVoPsCDQEESApGalhQ55OT8s0fM7OTFMfqsV3GD9J9FO4wP\n"
        "BlawHpQ5rbWGsyNYXnjXzGpmuyKl4xQBVdbx1tzh+1XlwqMhbXibMozo5U5De0oH\n"
        "A9z1Owbt3++3t+LykQDcHEtiKcvYt71by1X3J2IQOBAwWJ2jRjZQ5QJWaGXirPdR\n"
        "VwIDAQAB\n"
        "-----END PUBLIC KEY-----";

    auto privateKey = "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDAgBJHSAjCLOC/\n"
        "SP8bOPoT+BLUnqDBRd4ME0PtzisN2qH80/vw3qlY0rFrlgDK1MA6yirEsNEvb2mr\n"
        "nkfJHDnjszfmHB2YR8Txs6OeiC8dFEq7sDaIZXtqSQrRw/peAeBwlWVcFfbEJPvS\n"
        "chfh0OS8aFIrCumzWj7ddWG2dWg+wINAQRICkZqWFDnk5PyzR8zs5MUx+qxXcYP0\n"
        "n0U7jA8GVrAelDmttYazI1heeNfMama7IqXjFAFV1vHW3OH7VeXCoyFteJsyjOjl\n"
        "TkN7SgcD3PU7Bu3f77e34vKRANwcS2Ipy9i3vVvLVfcnYhA4EDBYnaNGNlDlAlZo\n"
        "ZeKs91FXAgMBAAECggEAKiO/HJiRxkQBvQ4TPlfWMsnjAWVqRnTve1A6VhQES8eZ\n"
        "H1oedGehxb51tVoEeWJiZFw+SYl1eX9XsAh5qXZC2+wvJ/HurpfDbq/G+RzRx3la\n"
        "NMUJ4wjoH+e2dR4EMFET20FxC1wJhX2dHL/6J2ZNtErX9fExIKB4U41vIvyHofis\n"
        "ABjyPMWsoDnFgJS2dYlXqDE9du2gXMq+vxyAKFuG5iLjtoaDGiY6hUx6eSUAclHd\n"
        "hRrmc1fftBWZUh1yr+yqH/VQGP0mVG3BIVvk7R75EST4+DxZcxxIE6NEOxFkS1Jc\n"
        "jeVR6AsLz3+rkP1/K4SKD3HzQ+fNWYWulAAFsnChSQKBgQD0OgTGhpxP0X9k6NBA\n"
        "urdZLGAePZaU+TUXwLL3+t6Upz7fJoh3bogkgbAUfjXDmrexXfIliMnm1KX9d4ZT\n"
        "TB3VpDsjiYK82sLMs0adb+9jJqignX/nxoJdsWpamP2DJwAr3621nVNYLutzp4rn\n"
        "dXKJYu1KtJdsQrsb/9mT87wD7wKBgQDJx7OxR992Ly8HB/GG9e+RCJVTHHwoYkaa\n"
        "HkGFL/sxfANcWbqzJdd6qnNwUIK32GaY8F5pxo12zcpaVGLPk6J78HxQrnx6gQH/\n"
        "KT3Bc9wT4M7nHIkt/Y879Z7BaiQ+2TafSdNWmobIB2H5X9zd0JoSs9gScbbaZ0kA\n"
        "eW+KEtkBGQKBgDCEEgzKEuU8Td1i7nPdY6zgRtvbCj3f368vRZ5DhNHtA21a/0MS\n"
        "fxMZfDwl8lJAOvuOGRthuBIV7j+S7elANrEJJgJiP8l6f7Ygawe9g8WjmV4Gy7Dk\n"
        "W2N3ahRDTiEurzcIAT8R2MusznM0NkDSsQUf1NnBVE9aVkcypStiANibAoGAXWaT\n"
        "Rvx987bjjd2fb1loCzpt5IrK7eaPx8c5jO0o2T8OTzE5urNJiv5bcSHTYEZLN4AM\n"
        "M+o0kUmw4R8unec4zyYCZVZfSFVvFy1/6Iw40vq8yz3qQd+c7aREWENJg84H+rOx\n"
        "n+Tnfq/sKgK1ufdVWlLlMaRxf6dPo2iSuNcAnAECgYActoBiupT5Kc2ZK/lCylJc\n"
        "3UpJwB4dhuXypOjqvDQ6uyUSVbyD3TvneyB+8hYnPMXXTDtW6ne5pCMcxibtkK2T\n"
        "Tmy283w8+RuGbK4+7ifgV97PUGrYFAmpqWhaympDCTp5WTwgKsmCDxX0B3bq77xW\n"
        "oao1npvUquuvWx6cUaQN7Q==\n"
        "-----END PRIVATE KEY-----";

    auto encryptedText = CryptoService::encryptWithRSA(plainText, publicKey);
    auto decryptedText = CryptoService::decryptWithRSA(encryptedText, privateKey);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(DecryptWithRSATest, DecryptionWithRSAMustBeFailedWithAnInvalidPrivateKey)
{
    auto plainText = "This text will be encrypted soon";

    auto publicKey = "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIASR0gIwizgv0j/Gzj6\n"
        "E/gS1J6gwUXeDBND7c4rDdqh/NP78N6pWNKxa5YAytTAOsoqxLDRL29pq55HyRw5\n"
        "47M35hwdmEfE8bOjnogvHRRKu7A2iGV7akkK0cP6XgHgcJVlXBX2xCT70nIX4dDk\n"
        "vGhSKwrps1o+3XVhtnVoPsCDQEESApGalhQ55OT8s0fM7OTFMfqsV3GD9J9FO4wP\n"
        "BlawHpQ5rbWGsyNYXnjXzGpmuyKl4xQBVdbx1tzh+1XlwqMhbXibMozo5U5De0oH\n"
        "A9z1Owbt3++3t+LykQDcHEtiKcvYt71by1X3J2IQOBAwWJ2jRjZQ5QJWaGXirPdR\n"
        "VwIDAQAB\n"
        "-----END PUBLIC KEY-----";

    auto privateKey = "-----BEGIN PRIVATE KEY-----\n"
        "SOME_INVALID_KEY/\n"
        "-----END PRIVATE KEY-----";

    auto encryptedText = CryptoService::encryptWithRSA(plainText, publicKey);

    try
    {
        auto decryptedText = CryptoService::decryptWithRSA(encryptedText, privateKey);

        FAIL() << "Expected InvalidPrivateKeyException";
    }
    catch (const InvalidPrivateKeyException& e)
    {
        EXPECT_EQ(std::string(e.what()), "RSA private key is invalid");
    }
    catch (...)
    {
        FAIL() << "Expected InvalidPrivateKeyException";
    }
}

TEST(DecryptWithRSATest, DecryptionWithRSAMustBeFailedWithAnCorruptedEncryptedText)
{
    auto encryptedText = "1";

    auto privateKey = "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDAgBJHSAjCLOC/\n"
        "SP8bOPoT+BLUnqDBRd4ME0PtzisN2qH80/vw3qlY0rFrlgDK1MA6yirEsNEvb2mr\n"
        "nkfJHDnjszfmHB2YR8Txs6OeiC8dFEq7sDaIZXtqSQrRw/peAeBwlWVcFfbEJPvS\n"
        "chfh0OS8aFIrCumzWj7ddWG2dWg+wINAQRICkZqWFDnk5PyzR8zs5MUx+qxXcYP0\n"
        "n0U7jA8GVrAelDmttYazI1heeNfMama7IqXjFAFV1vHW3OH7VeXCoyFteJsyjOjl\n"
        "TkN7SgcD3PU7Bu3f77e34vKRANwcS2Ipy9i3vVvLVfcnYhA4EDBYnaNGNlDlAlZo\n"
        "ZeKs91FXAgMBAAECggEAKiO/HJiRxkQBvQ4TPlfWMsnjAWVqRnTve1A6VhQES8eZ\n"
        "H1oedGehxb51tVoEeWJiZFw+SYl1eX9XsAh5qXZC2+wvJ/HurpfDbq/G+RzRx3la\n"
        "NMUJ4wjoH+e2dR4EMFET20FxC1wJhX2dHL/6J2ZNtErX9fExIKB4U41vIvyHofis\n"
        "ABjyPMWsoDnFgJS2dYlXqDE9du2gXMq+vxyAKFuG5iLjtoaDGiY6hUx6eSUAclHd\n"
        "hRrmc1fftBWZUh1yr+yqH/VQGP0mVG3BIVvk7R75EST4+DxZcxxIE6NEOxFkS1Jc\n"
        "jeVR6AsLz3+rkP1/K4SKD3HzQ+fNWYWulAAFsnChSQKBgQD0OgTGhpxP0X9k6NBA\n"
        "urdZLGAePZaU+TUXwLL3+t6Upz7fJoh3bogkgbAUfjXDmrexXfIliMnm1KX9d4ZT\n"
        "TB3VpDsjiYK82sLMs0adb+9jJqignX/nxoJdsWpamP2DJwAr3621nVNYLutzp4rn\n"
        "dXKJYu1KtJdsQrsb/9mT87wD7wKBgQDJx7OxR992Ly8HB/GG9e+RCJVTHHwoYkaa\n"
        "HkGFL/sxfANcWbqzJdd6qnNwUIK32GaY8F5pxo12zcpaVGLPk6J78HxQrnx6gQH/\n"
        "KT3Bc9wT4M7nHIkt/Y879Z7BaiQ+2TafSdNWmobIB2H5X9zd0JoSs9gScbbaZ0kA\n"
        "eW+KEtkBGQKBgDCEEgzKEuU8Td1i7nPdY6zgRtvbCj3f368vRZ5DhNHtA21a/0MS\n"
        "fxMZfDwl8lJAOvuOGRthuBIV7j+S7elANrEJJgJiP8l6f7Ygawe9g8WjmV4Gy7Dk\n"
        "W2N3ahRDTiEurzcIAT8R2MusznM0NkDSsQUf1NnBVE9aVkcypStiANibAoGAXWaT\n"
        "Rvx987bjjd2fb1loCzpt5IrK7eaPx8c5jO0o2T8OTzE5urNJiv5bcSHTYEZLN4AM\n"
        "M+o0kUmw4R8unec4zyYCZVZfSFVvFy1/6Iw40vq8yz3qQd+c7aREWENJg84H+rOx\n"
        "n+Tnfq/sKgK1ufdVWlLlMaRxf6dPo2iSuNcAnAECgYActoBiupT5Kc2ZK/lCylJc\n"
        "3UpJwB4dhuXypOjqvDQ6uyUSVbyD3TvneyB+8hYnPMXXTDtW6ne5pCMcxibtkK2T\n"
        "Tmy283w8+RuGbK4+7ifgV97PUGrYFAmpqWhaympDCTp5WTwgKsmCDxX0B3bq77xW\n"
        "oao1npvUquuvWx6cUaQN7Q==\n"
        "-----END PRIVATE KEY-----";

    try
    {
        auto decryptedText = CryptoService::decryptWithRSA(encryptedText, privateKey);

        FAIL() << "Expected CorruptedTextException";
    }
    catch (const CorruptedTextException& e)
    {
        EXPECT_EQ(std::string(e.what()), "Encrypted text is corrupted");
    }
    catch (...)
    {
        FAIL() << "Expected CorruptedTextException";
    }
}

TEST(HashTest, HashWithSHA256MustBeCompletedSuccessfully)
{
    std::string plainText = "This text will be hashed soon";

    auto hashText = CryptoService::hash(plainText);

    ASSERT_EQ(hashText, "d32448bab2777b376a5592e384146c3c0182ba589e2521bd0275f2cef6a50546") << "Hash is invalid";
}

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
