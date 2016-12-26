#ifndef _SET_2_HPP
#define _SET_2_HPP
    
#include <iostream>
#include <string>
#include <sstream>
#include <set_1.hpp>

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

    // Implements a block cipher in CBC mode
    // @param (string) plaintext input
    // @param (string) key
    // @param (string) initialization vector - use escape sequences 
    //     ex: "\x00\x00\x00\x00"
    // @returns (string) ciphertext
    std::string cbc_mode(const std::string &, const std::string &, 
            const std::string &);
}

#endif /* _SET_2_HPP */
