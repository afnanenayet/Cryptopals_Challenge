#ifndef _SET_2_HPP
#define _SET_2_HPP
    
#include <iostream>
#include <string>
#include <sstream>
#include <set_1.hpp>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cppcodec/base64_default_rfc4648.hpp>
#include <cryptopp/base64.h>

namespace set_2 {
    /* Runs the test cases for the challenges in set 2
     */
    void test_cases();

    /* Pads a block of bytes to a specified length by appending bytes 
     * using the PKCS#7 scheme. This appends bytes to ensure that 
     * the input is an even multiple of the desired block size
     * @param (string) the input string
     * @param (unsigned int) the desired block size
     * @returns a string that is padded to the desired block length
     */
    std::string pkcs_7_padding (const std::string &, const unsigned int);

    /* Implements AES 128 bit CBC block encryption
     * @param (string) plaintext input
     * @param (string) key
     * @param (string) initialization vector - use escape sequences 
     *     ex: "\x00\x00\x00\x00"s
     * @returns (string) ciphertext
     */
    std::string aes_128_cbc_encrypt(const std::string &, const std::string &, 
            const std::string &);

    /* Implements AES 128 bit CBC block encryption
     * @param (string) plaintext input
     * @param (string) key
     * @param (string) initialization vector - use escape sequences 
     *     ex: "\x00\x00\x00\x00"
     * @returns (string) ciphertext
     */
    std::string aes_128_cbc_decrypt(const std::string &, const std::string &, 
            const std::string &);

    /* XORs every element between two strings of the same length
     * @param (string) first string
     * @param (string) second string
     * @returns (string) the XOR result betwen the two strings
     */
    std::string xor_block_add(const std::string &, const std::string &);

    /* Print the binary representation of each character of a string to 
     * stdout
     *
     * @param (string) a string
     */
    void print_string_binary(const string &input);

    /* Decrypt a string using the CryptoPP library's CBC decryption
     *
     * @param (string) input: the input
     * @param (string) key: the key
     * @param (string) iv: the initialization vector
     */
    string aes_128_cbc_dec_cpp(const string &input, const string &key, 
            const string &iv);

    // ~~~~~~~~~~~~~~~~~~~~~~~~~ Challenge wrapper functions ~~~~~~~~~~~~~~~~~
    // Functions that are wrappers for the Cryptopals challenges

    /* Challenge 10
     * @param (string)
     * @param (string)
     * @param (string)
     * @returns (string)
     */
    std::string challenge_10_wrapper(const std::string &, const std::string &, 
            const std::string &);

    /* Decode a string encoded with base64 to regular ASCII text
     * @param (string) the input string encoded with base64
     * @returns (string) the decoded string
     */
    std::string base64_decode(const std::string &);

    /* Encode a string with base64
     * @param (string) the input string
     * @returns (string) a string encoded with base64
     */
    std::string base64_encode(const std::string &);
}

#endif /* _SET_2_HPP */
