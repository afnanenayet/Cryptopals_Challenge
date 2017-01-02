#ifndef _SET_2_HPP
#define _SET_2_HPP
    
#include <iostream>
#include <string>
#include <sstream>
#include <set_1.hpp>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cppcodec/base64_default_rfc4648.hpp>

namespace set_2 {
    // Runs the test cases for the challenges in set 2
    void test_cases();

    // Pads a block of bytes to a specified length by appending bytes 
    // using the PKCS#7 scheme. This appends bytes to ensure that 
    // the input is an even multiple of the desired block size
    // @param (string) the input string
    // @param (unsigned int) the desired block size
    // @returns a string that is padded to the desired block length
    std::string pkcs_7_padding (const std::string &, const unsigned int);

    // Implements AES 128 bit CBC block encryption
    // @param (string) plaintext input
    // @param (string) key
    // @param (string) initialization vector - use escape sequences 
    //     ex: "\x00\x00\x00\x00"
    // @returns (string) ciphertext
    std::string aes_128_cbc_encrypt(const std::string &, const std::string &, 
            const std::string &);

    // Implements AES 128 bit CBC block encryption
    // @param (string) plaintext input
    // @param (string) key
    // @param (string) initialization vector - use escape sequences 
    //     ex: "\x00\x00\x00\x00"
    // @returns (string) ciphertext
    std::string aes_128_cbc_decrypt(const std::string &, const std::string &, 
            const std::string &);

    // XORs every element between two strings of the same length
    // @param (string) first string
    // @param (string) second string
    // @returns (string) the XOR result betwen the two strings
    std::string xor_block_add(const std::string &, const std::string &);

    // ~~~~~~~~~~~~~~~~~~~~~~~~~ Challenge wrapper functions ~~~~~~~~~~~~~~~~~
    // Functions that are wrappers for the Cryptopals challenges

    // Challenge 10
    // @param (string)
    // @param (string)
    // @param (string)
    // @returns (string)
    std::string challenge_10_wrapper(const std::string &, const std::string &, 
            const std::string &);
}

#endif /* _SET_2_HPP */
