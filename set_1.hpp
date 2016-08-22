#include <string>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <climits>

namespace set_1 {
    // Converts a hex char to a decimal representation
	// cast as an unsigned char
    // will throw invalid_argument exception for if argument
    // is not a valid hex char
    // HELPER FUNCTION
    inline unsigned char hex_decode(unsigned char);

    // Converts a number to its hexadecimal character representation
    // Will throw invalid_argument exception if the number passed is not
    // between 0 and 16
    inline unsigned char hex_encode(unsigned char);

    // Converts a string of hexadecimal encoded characters to
    // a string of base 64 encoded characters 
    // CHALLENGE 1
    std::string hex_to_base64(const std::string &);

    // A function that takes two hexadecimal encoded strings
    // of equal length and returns their XOR combination
    // CHALLENGE 2
    std::string hex_xor_op(const std::string &, const std::string &);

    // Takes a string and performs a xor operation against each character
    // using the char key provided and returns the resultant string
    // NOTE: this does not respect any encodings - it just performs
    // the operation on each raw char
    std::string xor_op_sk(const std::string &, unsigned char);

    // Takes a hex encoded string that has been XOR'd against a single char,
    // finds the key, then returns the decrypted message
    // CHALLENGE 3
    std::string single_xor_decrypt(const std::string &);

    // Converts a hex encoded string to a standard ASCII encoded string
    inline std::string hex_to_text(std::string hex_string);

    // Runs all test cases and prints results to console
    // Prints 0 for each successful test case
    void test_cases();
}
