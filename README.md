# libcpp-crypto

Easy-to-use, symmetric (AES-256) and asymmetric (RSA) encryption and also hash (SHA-256) library for C++ (17+)

[![linux](https://github.com/leventkaragol/libcpp-crypto/actions/workflows/linux.yml/badge.svg)](https://github.com/leventkaragol/libcpp-crypto/actions/workflows/linux.yml)
[![windows](https://github.com/leventkaragol/libcpp-crypto/actions/workflows/windows.yml/badge.svg)](https://github.com/leventkaragol/libcpp-crypto/actions/workflows/windows.yml)


> [!TIP]
> Please read this document before using the library. I know, you don't have time but reading
> this document will save you time. I mean just this file, it's not long at all. Trial and error
> will cost you more time.

# Table of Contents

* [How to add it to my project](#how-to-add-it-to-my-project)
* [How to use? (Symmetric Encryption with AES)](#how-to-use-symmetric-encryption-with-aes)
* [How to use? (Hash with SHA-256)](#how-to-use-hash-with-sha-256)
* [How to use? (Asymmetric Encryption with RSA)](#how-to-use-asymmetric-encryption-with-rsa)
* [How do I generate Public/Private Keys?](#how-do-i-generate-publicprivate-keys)
* [Relationship between key size and max text length that can be encrypted](#relationship-between-key-size-and-max-text-length-that-can-be-encrypted)
* [How to handle Exceptions (AES)?](#how-to-handle-exceptions-aes)
* [How to handle Exceptions (RSA)?](#how-to-handle-exceptions-rsa)
* [Semantic Versioning](#semantic-versioning)
* [Full function list](#full-function-list)
* [License](#license)
* [Contact](#contact)

## How to add it to my project?

This is a header only library. So actually, all you need is to add the libcpp-crypto.hpp file
in src folder to your project and start using it with #include.

But this library is a kind of OpenSSL wrapper that uses OpenSSL under the hood. So, you also need to add OpenSSL to
your project before to use it.

You can find usage examples in the examples folder, also find a sample CMakeLists.txt file content below.

```cmake
cmake_minimum_required(VERSION 3.14)

project(myProject)

find_package(OpenSSL REQUIRED)

add_executable(myProject main.cpp)

target_link_libraries(myProject PRIVATE libcpp-crypto OpenSSL::SSL OpenSSL::Crypto)

```

## How to use? (Symmetric Encryption with AES)

To encrypt and decrypt the given text with AES-256, all you need to do is call the **"encryptWithAES"** and
**"decryptWithAES"** functions with a key you choose for encryption.

```cpp
#include "libcpp-crypto.hpp"

using namespace lklibs;

int main() {

    auto plainText = "This text will be encrypted soon";
    auto key = "mySecretKey";
    
    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    
    std::cout << "Encrypted Text: " << encryptedText << std::endl;
    
    auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);
    
    std::cout << "Decrypted Text: " << decryptedText << std::endl;

    return 0;
}
```

> [!TIP]
> In fact, the key you need to use with AES-256 must be 32 characters long. However, the library adds a sufficient
> amount of "0" to the end of keys shorter than 32 characters, and ignores the last parts of keys longer than
> 32 characters, allowing you to use the key you want without any errors.

## How to use? (Hash with SHA-256)

All you need to do is call the **"hash"** function to hash the given text with SHA-256.

```cpp
#include "libcpp-crypto.hpp"

using namespace lklibs;

int main() {

    auto plainText = "This text will be hashed soon";
    
    auto hashText = CryptoService::hash(plainText);
    
    std::cout << "Hash: " << hashText << std::endl;

    return 0;
}
```

## How to use? (Asymmetric Encryption with RSA)

To encrypt and decrypt the given text with RSA, all you need to do is call the **"encryptWithRSA"** and
**"decryptWithRSA"** functions with a pair of public/private key.

> [!TIP]
> If you don't know how to generate public/private keys, please see the next topic

```cpp
#include "libcpp-crypto.hpp"

using namespace lklibs;

int main() {

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
    
    std::cout << "Encrypted Text: " << encryptedText << std::endl;
    
    auto decryptedText = CryptoService::decryptWithRSA(encryptedText, privateKey);
    
    std::cout << "Decrypted Text: " << decryptedText << std::endl;

    return 0;
}
```

## How do I generate Public/Private Keys?

You have two different options to create a Public and Private key pair. The first option, and the easier one, is to use the
generateRSAKeyPair function in the library, passing the desired key length as a parameter. Below is a sample code for this usage.

```cpp
    auto keyPair = CryptoService::generateRSAKeyPair(2048);

    std::cout << "2048 bit Public RSA Key:" << std::endl << keyPair.publicKey << std::endl;
    std::cout << "2048 bit Private RSA Key:" << std::endl << keyPair.privateKey << std::endl;
```

> [!TIP]
> If you are not sure of the key length you will need, please see the next topic


Optionally, you can also pass a passphrase as follows to the generateRSAKeyPair function during key creation. In this case,
you will need to pass this passphrase to the decryptWithRSA function to decrypt the text.

```cpp
    auto keyPair = CryptoService::generateRSAKeyPair(2048, "myPassphrase");

    std::cout << "2048 bit Public RSA Key (with passphrase):" << std::endl << keyPair.publicKey << std::endl;
    std::cout << "2048 bit Private RSA Key (with passphrase):" << std::endl << keyPair.privateKey << std::endl;
```

As a second option, if OpenSSL is installed on your system, you can use the necessary OpenSSL commands from the 
command line to create a Public and Private key pair. As the first step in this option, when you run it by typing 
the following line on the command line, a text file named "private_key.pem" will be created containing the private
key information.

```bash
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

Then, when you run it by typing the following line on the command line, a text file named "public_key.pem" will be created
containing the public key information for this private key.

```bash
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

## Relationship between key size and max text length that can be encrypted

The size of the Key used during asymmetric encryption with RSA is not only related to the security of the encryption
process, but also determines what the longest text that can be encrypted with this key can be. Basically, the longest text
that can be encrypted with a 2<sup>x</sup> bit key can be calculated as 2<sup>x-3</sup>-11 for ASCII character set. Other
character sets can take up twice. I am sharing the table below for a quick reference.

| Key Bits | Maximum Text Length |
|----------|---------------------|
| 2048     | 245                 |
| 4096     | 501                 |
| 8192     | 1013                |
| 16384    | 2037                |
| 32768    | 4085                |
| 65536    | 8181                |

> [!IMPORTANT]
> Do not think that you can easily create a longer key to encrypt a longer text with RSA. Each row in the table consumes
> 4 times more CPU power during encryption/decryption process than the row above. Additionally, generating a 65K bit key takes
> time and requires a lot of patience, even for a high-end computer.

> [!CAUTION]
> 1024-bit RSA keys are not secure in the face of today's increasing computing power and advanced factorization algorithms. 
> Please use keys of at least 2048 bits.

## How to handle Exceptions (AES)?

There are two main Exceptions you may encounter when using the library for AES encryption. The first one is the **"InvalidKeyException"**
you will receive if the encryption key of the text you want to decrypt is incorrect, and the second one is the
**"CorruptedTextException"** you will receive if the text you want to decrypt is invalid.

The code below shows you how to catch the Exception thrown in case of an invalid encryption key.

```cpp
#include "libcpp-crypto.hpp"

using namespace lklibs;

int main() {

    auto plainText = "This text will be encrypted soon";
    auto key = "mySecretKey";
    auto invalidKey = "invalidKey";
    
    auto encryptedText = CryptoService::encryptWithAES(plainText, key);
    
    try
    {
        auto decryptedText = CryptoService::decryptWithAES(encryptedText, invalidKey);
    }
    catch (const InvalidKeyException& e)
    {
        std::cerr << e.what() << std::endl; // Encryption key does not match the original encryption key 
    }
    
    return 0;
}
```

The code below also shows you how to catch the Exception thrown when you try to decrypt and invalid text.

```cpp
#include "libcpp-crypto.hpp"

using namespace lklibs;

int main() {

    auto encryptedText = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    auto key = "mySecretKey";
    
    try
    {
        auto decryptedText = CryptoService::decryptWithAES(encryptedText, key);
    }
    catch (const CorruptedTextException& e)
    {
        std::cerr << e.what() << std::endl; // Encrypted text is corrupted 
    }
    
    return 0;
}
```

## How to handle Exceptions (RSA)?

The exception part for the RSA side is a little different. If the public and private keys used are not correct,
**"InvalidPublicKeyException"** and **"InvalidPrivateKeyException"** are thrown. However, the structure of the keys
used must be corrupt to throw these exceptions. If you use incompatible but structurally valid keys, no exception
will be thrown. However, the text obtained after decryption will consist of just meaningless characters.

```cpp
#include "libcpp-crypto.hpp"

using namespace lklibs;

int main() {

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
    }
    catch (const InvalidPrivateKeyException& e)
    {
        std::cerr << e.what() << std::endl; // RSA private key is invalid
    }
    
    return 0;
}
```

## Semantic Versioning

Versioning of the library is done using conventional semantic versioning. Accordingly,
in the versioning made as **MAJOR.MINOR.PATCH**;

**PATCH:** Includes possible Bug&Fixes and improvements. You definitely want to get this.

**MINOR:** Additional functionality added via backwards compatibility. You probably want to
get this, it doesn't hurt.

**MAJOR:** Additional functionality that breaks backwards compatibility. You'll need to know
what's changed before you get it, and you'll probably have to make changes to your own code.
If I publish something like this, I will definitely add the changes required for migration
section to the documentation.

## Full function list

You can find the complete list of functions in the library below.

> [!TIP]
> All functions and parameters descriptions are also available within the code as comment for IDEs.

```cpp
std::string encryptWithAES(const std::string& plaintext, const std::string& key);

std::string decryptWithAES(const std::string& ciphertext, const std::string& key);

RSAKeyPair generateRSAKeyPair(int keyLength, const std::string& passphrase = "");

std::string encryptWithRSA(const std::string& plaintext, const std::string& publicKeyStr);

std::string decryptWithRSA(const std::string& ciphertext, const std::string& privateKeyStr);

std::string hash(const std::string& text);
```

## License

MIT License

Copyright (c) 2024 Levent KARAGÖL

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Contact

If you have problems regarding the library, please open an
[issue on GitHub](https://github.com/leventkaragol/libcpp-crypto/issues/new).
Please describe your request, issue, or question in as much detail as possible
and also include the version of your compiler and operating system, as well as
the version of the library you are using. Before opening a new issue, please
confirm that the topic is not already exists in closed issues.