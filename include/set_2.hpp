#ifndef _SET_2_HPP
#define _SET_2_HPP
    
#include <iostream>
#include <string>
#include <sstream>

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
}

#endif /* _SET_2_HPP */
