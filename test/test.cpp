#include "libcpp-crypto.hpp"
#include <gtest/gtest.h>

using namespace lklibs;

TEST(EncryptWithAESTest, EncryptionWithAESMustBeCompletedSuccessfullyWithAValidKey)
{
    auto plainText = "Test message to be used during tests";
    auto key = "mySecretKey";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);

    ASSERT_FALSE(encryptedText.empty()) << "encryptedText is empty";
}

TEST(DecryptWithAESTest, DecryptionWithAESMustBeCompletedSuccessfullyWithAValidKey)
{
    auto plainText = "Test message to be used during tests";
    auto key = "mySecretKey";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(DecryptWithAESTest, DecryptionWithAESMustBeCompletedSuccessfullyForSpecialCharsWithAValidKey)
{
    auto plainText = "Test message to be used during tests with special characters: !@#$%^&*()_+{}|:<>?~`-=[]\\;',./öçşığüÖÇŞİĞÜ";
    auto key = "mySecretKey";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(DecryptWithAESTest, DecryptionWithAESMustBeFailedWithAnInvalidKey)
{
    auto plainText = "Test message to be used during tests";
    auto key = "mySecretKey";
    auto invalidKey = "invalidKey";

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
    auto key = "mySecretKey";

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
    auto plainText = "Test message to be used during tests";
    auto key = "123";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(AESKeyTest, AESEncryptionShouldBePossibleWithAKeyLargerThan32Characters)
{
    auto plainText = "Test message to be used during tests";
    auto key = "abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_+{}|:<>?~`-=[]\\;',./";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(AESKeyTest, AESEncryptionShouldBePossibleWithA32CharactersKey)
{
    auto plainText = "Test message to be used during tests";
    auto key = "abcdefghijklmnopqrstuvwxyz123456";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(AESKeyTest, AESEncryptionMustBePossibleWithAKeyContainingSpecialCharacters)
{
    auto plainText = "Test message to be used during tests";
    auto key = "!@#$%^&*()_+{}|:<>?~`-=[]\\;',./";

    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(RSAKeyTest, PublicPrivateKeyPairForRSAMustBeSuccessfullyGeneratedWithoutPassphrase)
{
    auto keyPair = CryptoService::generateRSAKeyPair(2048);

    ASSERT_FALSE(keyPair.publicKey.empty()) << "publicKey is empty";
    ASSERT_FALSE(keyPair.privateKey.empty()) << "privateKey is empty";
}

TEST(RSAKeyTest, PublicPrivateKeyPairForRSAMustBeSuccessfullyGeneratedWithPassphrase)
{
    auto keyPair = CryptoService::generateRSAKeyPair(2048, "myPassphrase");

    ASSERT_FALSE(keyPair.publicKey.empty()) << "publicKey is empty";
    ASSERT_FALSE(keyPair.privateKey.empty()) << "privateKey is empty";
}

TEST(RSAKeyTest, GeneratedRSAKeyPairShouldBeUsedSuccessfullyWithoutPassphrase)
{
    auto keyPair = CryptoService::generateRSAKeyPair(2048);

    auto plainText = "This text will be encrypted soon";

    auto encryptedText = CryptoService::encryptWithRSA(plainText, keyPair.publicKey);
    auto decryptedText = CryptoService::decryptWithRSA(encryptedText, keyPair.privateKey);

    ASSERT_EQ(decryptedText, plainText) << "decryptedText is invalid";
}

TEST(RSAKeyTest, GeneratedRSAKeyPairShouldBeUsedSuccessfullyWitPassphrase)
{
    auto keyPair = CryptoService::generateRSAKeyPair(2048, "myPassphrase");

    auto plainText = "This text will be encrypted soon";

    auto encryptedText = CryptoService::encryptWithRSA(plainText, keyPair.publicKey);
    auto decryptedText = CryptoService::decryptWithRSA(encryptedText, keyPair.privateKey, "myPassphrase");

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

TEST(DecryptWithRSATest, DecryptionWithRSAMustBeCompletedSuccessfullyWithAValidPrivateKeyWithoutPassphrase)
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

TEST(DecryptWithRSATest, DecryptionWithRSAMustBeCompletedSuccessfullyWithAValidPrivateKeyWithPassphrase)
{
    auto plainText = "This text will be encrypted soon";

    auto publicKey = "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq6s5i6Nn1OrfbKzY6wnM\n"
        "8VgpZfiFkSXE/ncuLs6wxWAb/OmY8jtqzJSwCZxoKjzLQrt7kVYjTTAu4oAM/GdP\n"
        "ufE4wvfrs9gqOYXcU31SgKNaffdLETHuTMsgBqhsmHHd872XgOSNUgP9ma5fvYKA\n"
        "+fVhGdSkKfGai3NVS0UaZTJSc8HAWcqMMqtO17YnN8MD/nkNC4hEyBkBdJ/imfg9\n"
        "1LbVEMn8uEM02kKLz7dMmcdFdAwc1WqCNv1Jl5MZrzapZU6n/wbn1tRUP+2Ug/PW\n"
        "wss6bOfIXPX2ZPGT+Z90G45xbPHOpTvzH8d/P8eQxZdyx3ZnZJ9xnghrwJLS1pBI\n"
        "6wIDAQAB\n"
        "-----END PUBLIC KEY-----";

    auto privateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "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\n"
        "-----END ENCRYPTED PRIVATE KEY-----";

    auto encryptedText = CryptoService::encryptWithRSA(plainText, publicKey);
    auto decryptedText = CryptoService::decryptWithRSA(encryptedText, privateKey, "myPassphrase");

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
        EXPECT_EQ(std::string(e.what()), "RSA private key is invalid or passphrase is incorrect");
    }
    catch (...)
    {
        FAIL() << "Expected InvalidPrivateKeyException";
    }
}

TEST(DecryptWithRSATest, DecryptionWithRSAMustBeFailedWithAnInvalidPassphrase)
{
    auto plainText = "This text will be encrypted soon";

    auto publicKey = "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq6s5i6Nn1OrfbKzY6wnM\n"
        "8VgpZfiFkSXE/ncuLs6wxWAb/OmY8jtqzJSwCZxoKjzLQrt7kVYjTTAu4oAM/GdP\n"
        "ufE4wvfrs9gqOYXcU31SgKNaffdLETHuTMsgBqhsmHHd872XgOSNUgP9ma5fvYKA\n"
        "+fVhGdSkKfGai3NVS0UaZTJSc8HAWcqMMqtO17YnN8MD/nkNC4hEyBkBdJ/imfg9\n"
        "1LbVEMn8uEM02kKLz7dMmcdFdAwc1WqCNv1Jl5MZrzapZU6n/wbn1tRUP+2Ug/PW\n"
        "wss6bOfIXPX2ZPGT+Z90G45xbPHOpTvzH8d/P8eQxZdyx3ZnZJ9xnghrwJLS1pBI\n"
        "6wIDAQAB\n"
        "-----END PUBLIC KEY-----";

    auto privateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "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\n"
        "-----END ENCRYPTED PRIVATE KEY-----";

    auto encryptedText = CryptoService::encryptWithRSA(plainText, publicKey);

    try
    {
        auto decryptedText = CryptoService::decryptWithRSA(encryptedText, privateKey, "invalidPassphrase");

        FAIL() << "Expected InvalidPrivateKeyException";
    }
    catch (const InvalidPrivateKeyException& e)
    {
        EXPECT_EQ(std::string(e.what()), "RSA private key is invalid or passphrase is incorrect");
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
    auto plainText = "This text will be hashed soon";

    auto hashText = CryptoService::hash(plainText);

    ASSERT_EQ(hashText, "d32448bab2777b376a5592e384146c3c0182ba589e2521bd0275f2cef6a50546") << "Hash is invalid";
}

TEST(HmacSha256Test, HashWithHMACSHA256MustBeCompletedSuccessfully)
{
    const auto plainText = "This text will be hashed soon";
    const auto key = "mySecretKey";

    const auto hashText = CryptoService::hmacSha256(plainText, key);

    ASSERT_EQ(hashText, "875dae56af4cb9c9c1b2e7f30e28704da4f1933bf85bb180409761f9c4721186") << "Hash is invalid";
}

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
