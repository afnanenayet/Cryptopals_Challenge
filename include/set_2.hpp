/* set_2.hpp    Afnan Enayet
 *
 * Header file for the code that corresponds to the solutions for the problems 
 * found in set 2 of the CryptoPals challenge. These functions are encased in 
 * the "set_2" namespace for clarity
 */
 
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
#include <cryptopp/osrng.h>

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
    void print_string_binary(const std::string &);

    /* Decrypt a string using the CryptoPP library's CBC decryption
     *
     * @param (string) input: the input
     * @param (string) key: the key
     * @param (string) iv: the initialization vector
     */
    std::string aes_128_cbc_dec_cpp(const std::string &, const std::string &, 
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

    /* This function generates a random 16 byte AES key using the CryptoPP 
     * PRNG. TODO
     *
     * @returns (string) a random key of 16 bytes
     */
    std::string gen_aes_key();

    /* Randomly encrypts a given input using CBC or ECB encryption with a 
     * randomly generated key. Also appends and prepends 5-10 random bytes 
     * to the input before encryption TODO
     *
     * @param (string) input
     * @returns (string) encrypted input
     */ 
    std::string encryption_oracle(const std::string &);


    /* Detects if an some encrypted string was encrypted using ECB or 
     * CBC. If it was encrypted using ECB, the function returns true. 
     * If the input was encrypted using CBC, the function will return 
     * false TODO
     *
     * @param (string) the encrypted input
     * @returns (string) if the input was encrypted using ECB
     */
    bool is_ecb_encrypted(const std::string &);

    /* ~~~~~~~~~~~~~~~~~~ Challenge wrapper functions ~~~~~~~~~~~~~~~ */
    // Functions that are wrappers for the Cryptopals challenges

    /* Challenge 10
     * @param (string)
     * @param (string)
     * @param (string)
     * @returns (string)
     */
    std::string challenge_10_wrapper(const std::string &, const std::string &, 
            const std::string &);

    /* Challenge 11
     * @returns (bool) whether challenge was successfully executed
     */
    bool challenge_11_wrapper();
}

#endif /* _SET_2_HPP */
