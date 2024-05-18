/*

Modern, easy-to-use, symmetric (AES-256) and asymmetric (RSA) encryption and also hash (SHA-256) library for C++ (17+)
version 1.0.0
https://github.com/leventkaragol/libcpp-crypto

If you encounter any issues, please submit a ticket at https://github.com/leventkaragol/libcpp-crypto/issues

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

*/

#ifndef LIBCPP_CRYPTO_HPP
#define LIBCPP_CRYPTO_HPP

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <memory>
#include <array>
#include <stdexcept>
#include <iostream>

namespace lklibs
{
    class Base64Converter
    {
    public:
        static std::string encode(const std::string& input)
        {
            static const std::string base64_chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";

            std::string ret;
            int i = 0;
            unsigned char char_array_3[3];
            unsigned char char_array_4[4];

            for (auto c : input)
            {
                char_array_3[i++] = c;

                if (i == 3)
                {
                    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                    char_array_4[3] = char_array_3[2] & 0x3f;

                    for (i = 0; i < 4; i++)
                    {
                        ret += base64_chars[char_array_4[i]];
                    }

                    i = 0;
                }
            }

            if (i)
            {
                for (int j = i; j < 3; j++)
                {
                    char_array_3[j] = '\0';
                }

                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

                for (int j = 0; j < i + 1; j++)
                {
                    ret += base64_chars[char_array_4[j]];
                }

                while (i++ < 3)
                {
                    ret += '=';
                }
            }

            return ret;
        }

        static std::string decode(const std::string& input)
        {
            static const std::string base64_chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";

            std::string ret;
            int i = 0;
            unsigned char char_array_4[4], char_array_3[3];

            for (auto c : input)
            {
                if (c == '=' || !isBase64(c))
                {
                    break;
                }

                char_array_4[i++] = c;
                if (i == 4)
                {
                    for (i = 0; i < 4; i++)
                    {
                        char_array_4[i] = base64_chars.find(char_array_4[i]);
                    }

                    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                    for (i = 0; i < 3; i++)
                    {
                        ret += char_array_3[i];
                    }

                    i = 0;
                }
            }

            if (i)
            {
                for (int j = i; j < 4; j++)
                {
                    char_array_4[j] = 0;
                }

                for (unsigned char& j : char_array_4)
                {
                    j = base64_chars.find(j);
                }

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (int j = 0; j < i - 1; j++)
                {
                    ret += char_array_3[j];
                }
            }

            return ret;
        }

    private:
        static bool isBase64(unsigned char c)
        {
            return (isalnum(c) || (c == '+') || (c == '/'));
        }
    };

    class CryptoException : public std::runtime_error
    {
    public:
        explicit CryptoException(const std::string& message) : std::runtime_error(message)
        {
        }
    };

    class EncryptionInitException : public CryptoException
    {
    public:
        explicit EncryptionInitException(const std::string& message) : CryptoException(message)
        {
        }
    };

    class EncryptionUpdateException : public CryptoException
    {
    public:
        explicit EncryptionUpdateException(const std::string& message) : CryptoException(message)
        {
        }
    };

    class EncryptionFinalException : public CryptoException
    {
    public:
        explicit EncryptionFinalException(const std::string& message) : CryptoException(message)
        {
        }
    };

    class DecryptionInitException : public CryptoException
    {
    public:
        explicit DecryptionInitException(const std::string& message) : CryptoException(message)
        {
        }
    };

    class DecryptionUpdateException : public CryptoException
    {
    public:
        explicit DecryptionUpdateException(const std::string& message) : CryptoException(message)
        {
        }
    };

    class InvalidKeyException : public CryptoException
    {
    public:
        explicit InvalidKeyException(const std::string& message) : CryptoException(message)
        {
        }
    };

    class CorruptedTextException : public CryptoException
    {
    public:
        explicit CorruptedTextException(const std::string& message) : CryptoException(message)
        {
        }
    };

    class IVGenerationException : public CryptoException
    {
    public:
        explicit IVGenerationException(const std::string& message) : CryptoException(message)
        {
        }
    };

    class CryptoService
    {
    public:
        static std::string encryptWithAES(const std::string& plaintext, const std::string& key)
        {
            std::string adjustedKey = adjustKeyLength(key);

            std::vector<unsigned char> iv(AES_BLOCK_SIZE);
            generateRandomIV(iv);

            std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);

            int ciphertext_len = encrypt(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length(), reinterpret_cast<const unsigned char*>(adjustedKey.c_str()), iv.data(), ciphertext.data());

            ciphertext.resize(ciphertext_len);

            std::string encrypted = std::string(iv.begin(), iv.end()) + std::string(ciphertext.begin(), ciphertext.end());
            return Base64Converter::encode(encrypted);
        }

        static std::string decryptWithAES(const std::string& ciphertext, const std::string& key)
        {
            std::string adjustedKey = adjustKeyLength(key);

            auto encryptedText = Base64Converter::decode(ciphertext);

            std::vector<unsigned char> iv(AES_BLOCK_SIZE);
            std::copy(encryptedText.begin(), encryptedText.begin() + AES_BLOCK_SIZE, iv.begin());

            std::vector<unsigned char> plaintext(encryptedText.size() - AES_BLOCK_SIZE);

            int plaintext_len = decrypt(reinterpret_cast<const unsigned char*>(encryptedText.data() + AES_BLOCK_SIZE), encryptedText.size() - AES_BLOCK_SIZE, reinterpret_cast<const unsigned char*>(adjustedKey.c_str()), iv.data(), plaintext.data());

            plaintext.resize(plaintext_len);

            return std::string{plaintext.begin(), plaintext.end()};
        }

    private:
        struct EVP_CIPHER_CTX_Deleter
        {
            void operator()(EVP_CIPHER_CTX* ptr) const { EVP_CIPHER_CTX_free(ptr); }
        };

        static int encrypt(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, unsigned char* iv, unsigned char* ciphertext)
        {
            std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());

            int len;
            int ciphertext_len;

            if (!ctx)
            {
                throw EncryptionInitException("Failed to create OpenSSL context for encryption");
            }

            if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key, iv))
            {
                throw EncryptionInitException("Failed to initialize OpenSSL encryption operation");
            }

            if (1 != EVP_EncryptUpdate(ctx.get(), ciphertext, &len, plaintext, plaintext_len))
            {
                throw EncryptionUpdateException("Failed to update OpenSSL encryption operation");
            }

            ciphertext_len = len;

            if (1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext + len, &len))
            {
                throw EncryptionFinalException("Failed to finalize OpenSSL encryption operation");
            }

            ciphertext_len += len;

            return ciphertext_len;
        }

        static int decrypt(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, unsigned char* iv, unsigned char* plaintext)
        {
            std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());

            int len;
            int plaintext_len;

            if (!ctx)
            {
                throw DecryptionInitException("Failed to create OpenSSL context for decryption");
            }

            if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key, iv))
            {
                throw DecryptionInitException("Failed to initialize OpenSSL decryption operation");
            }

            if (1 != EVP_DecryptUpdate(ctx.get(), plaintext, &len, ciphertext, ciphertext_len))
            {
                throw DecryptionUpdateException("Failed to update OpenSSL decryption operation");
            }

            plaintext_len = len;

            if (1 != EVP_DecryptFinal_ex(ctx.get(), plaintext + len, &len))
            {
                if (ERR_GET_REASON(ERR_peek_last_error()) == EVP_R_BAD_DECRYPT)
                {
                    throw InvalidKeyException("Encryption key does not match the original encryption key");
                }
                else
                {
                    throw CorruptedTextException("Encrypted text is corrupted");
                }
            }

            plaintext_len += len;

            return plaintext_len;
        }

        static void generateRandomIV(std::vector<unsigned char>& iv)
        {
            if (!RAND_bytes(iv.data(), AES_BLOCK_SIZE))
            {
                throw IVGenerationException("Failed to generate random IV");
            }
        }

        static std::string adjustKeyLength(const std::string& key)
        {
            if (key.size() == 32)
            {
                return key;
            }
            else if (key.size() > 32)
            {
                return key.substr(0, 32);
            }
            else
            {
                std::string adjusted_key = key;
                adjusted_key.append(32 - key.size(), '0');
                return adjusted_key;
            }
        }
    };
}
#endif //LIBCPP_CRYPTO_HPP
