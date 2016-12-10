#ifndef _SET_1_HPP_
#define _SET_1_HPP_

#include <string>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <limits>
#include <map>
#include <cmath>
#include <cctype>
#include <fstream>
#include <bitset>
#include <vector>
#include <numeric>
#include <sstream>
#include <tuple>

namespace set_1 {
const std::string base64_cipher =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

// Converts a hex char to a decimal representation
// cast as an unsigned char
// will throw invalid_argument exception for if argument
// is not a valid hex char
// @param a valid hex char represented in ASCII or UTF-8
// NOTE: your system must use an encoding that places numbers and
// letters sequentially for the chars: A-F, a-f, and 0-9
inline unsigned char hex_decode(unsigned char);

// Converts a string of ASCII chars into a string of hex
// encoded characters
// @param: a plaintext string
inline std::string hex_encode_str(const std::string &);

// Converts a number to its hexadecimal character representation
// Will throw invalid_argument exception if the number passed is not
// between 0 and 16
// @param a valid hex char (from 0 to F - inclusive)
inline unsigned char hex_encode(unsigned char);

// Converts a string of hexadecimal encoded characters to
// a string of base 64 encoded characters
// @param a hex encoded string
// CHALLENGE 1
std::string hex_to_base64(const std::string &);

// A function that takes two hexadecimal encoded strings
// of equal length and returns their XOR combination
// @param a hex encoded string, @param a hex encoded string of
// the same length
// CHALLENGE 2
std::string hex_xor_op(const std::string &, const std::string &);

// Takes a string and performs a xor operation against each character
// using the char key provided and returns the resultant string
// NOTE: this does not respect any encodings - it just performs
// the operation on each raw char
// @param a string, @param an unsigned char between 0 and 255 inclusive
std::string xor_op_sk(const std::string &, unsigned char);

// Takes a hex encoded string that has been XOR'd against a single char,
// finds the key, then returns the decrypted message
// @param a hex encoded string
// CHALLENGE 3
std::string single_xor_decrypt(const std::string &);

// Analyzes a hex encoded string and returns the most likely
// key used to encrypt it
// @param a xor encoded string
unsigned char single_xor_decrypt_key(const std::string &xor_encoded_string);

// Converts a hex encoded string to a standard ASCII encoded string
// @param a hex encoded string
inline std::string hex_to_text(const std::string &);

// Runs all test cases and prints results to console
// Prints 0 for each successful test case
void test_cases();

// Analyzes a string and returns a number corresponding
// to how far off the frequency is in the given string
// @param an english  string
double freqa_ranking(std::string);

// Analyzes a string and returns the ratio of characters that are
// numerical (excluding whitespace)
// @param a non encoded normal string
double alpha_ranking(const std::string &);

// Analyzes a series of hex encoded strings and returns a string
// that has been detected to be using a single character XOR
// cipher
// CHALLENGE 4
// @param a string with the filename that contains the strings
std::string detect_schar_xor(const std::string &);

// Encrypts a string against a multi-character key
// and returns the encrypted result as a
// hex encoded string
// @param a key string
// @param a message to be encoded (plaintext)
std::string rep_xor_encrypt(const std::string &, const std::string &);

// Decrypts a hex encoded string encrypted with a repeating XOR key
// and returns the decrypted result as a string
// @param the file name of the stored hex string
// @param the minimum size (in bytes) of the guessed key
// @param the maximum size (in bytes) of the guessed key
std::tuple<std::string, std::string> rep_xor_decrypt(const std::string &, 
                                                     const unsigned int,
                                                     const unsigned int);

// Computes the Hamming distance between two strings
// @param any valid string
// @param any valid string
unsigned int hamming_distance(const std::string &, const std::string &);

// Returns the most likely key size for a string that has been encrypted
// with a repeating XOR key
// @param a xor encoded string
// @param the minimum key size (for guessing)
// @param the maximum key size (for guessing)
// @param the number of key pairs to evaluate
// @param the number of likely key size candidates to return
std::vector <unsigned int> xor_key_size_bf(const std::string &, 
                             const unsigned int,
                             const unsigned int, 
                             const unsigned int, 
                             const unsigned int);

// Returns the most likely key sizes for a string that has been encrypted
// with a repeating XOR key
// @param a xor encoded string
// @param the minimum possible key size (default 1)
// @param the maximum possible key size (default 40)
// @param the number of key pairs to evaluate (default 1)
// @param the number of guessed key sizes to return (default 1)
unsigned int xor_key_size_bf_multi(const std::string &, const unsigned int &,
                                   const unsigned int &, const unsigned int &,
                                   const unsigned int &);
}

#endif // _SET_1_HPP
