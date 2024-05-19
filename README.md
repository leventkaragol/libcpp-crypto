# libcpp-crypto

Modern, easy-to-use, symmetric (AES-256) and asymmetric (RSA) encryption and also hash (SHA-256) library for C++ (17+)

[![linux](https://github.com/leventkaragol/libcpp-crypto/actions/workflows/linux.yml/badge.svg)](https://github.com/leventkaragol/libcpp-crypto/actions/workflows/linux.yml)
[![windows](https://github.com/leventkaragol/libcpp-crypto/actions/workflows/windows.yml/badge.svg)](https://github.com/leventkaragol/libcpp-crypto/actions/workflows/windows.yml)


> [!TIP]
> Please read this document before using the library. I know, you don't have time but reading
> this document will save you time. I mean just this file, it's not long at all. Trial and error
> will cost you more time.

# Table of Contents

* [How to add it to my project](#how-to-add-it-to-my-project)
* [How to use? (Symmetric Encryption with AES)](#how-to-use-symmetric-encryption-with-aes)
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

To encrypt and decrypt the given text with AES-256, all you need to do is call the static "encryptWithAES" and
"decryptWithAES" methods with a key you choose for encryption.

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


## How to handle Exceptions?

There are two main Exceptions you may encounter when using the library. The first one is the "InvalidKeyException"
you will receive if the encryption key of the text you want to decrypt is incorrect, and the second one is the
"CorruptedTextException" you will receive if the text you want to decrypt is invalid.

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

You can find the complete list of functions in the library below. All methods in this library are static methods.
You don't need to create an instance of the class to use them.

> [!TIP]
> All methods and parameters descriptions are also available within the code as comment for IDEs.

```cpp
static std::string encryptWithAES(const std::string& plaintext, const std::string& key);

static std::string decryptWithAES(const std::string& ciphertext, const std::string& key);
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