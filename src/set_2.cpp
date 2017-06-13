#include "set_2.hpp"

using std::string;
using std::cout;
using std::endl;
using namespace CryptoPP;
using namespace std::literals::string_literals;

namespace set_2 {
    /* Computes the number of bytes to add to the string, converts that 
     * number to a string, then adds it repeatedly to the 
     */
    string pkcs_7_padding(const string &input_string,  const unsigned int 
            block_size) {
        // The number of bytes we need to add to make the string a multiple 
        // of the desired block size
        auto rem_bytes = block_size - (input_string.length() % block_size); 

        // Initializing a stream with the input string so we can easily append 
        // the hex chars for padding
        std::stringstream padded_string_stream(input_string, std::ios_base::app 
                | std::ios_base::out);

        // Adding the byte string repeatedly to the padded string so it will 
        // have as many bytes as desired
        for (auto i = 0; i < rem_bytes; i++) {
            padded_string_stream << std::hex << rem_bytes;
        }

        return padded_string_stream.str();
    }

    /* Adds characters by XOR'ing each character in two equal length strings. 
     * Will throw an exception if the strings are not of the same length
     */
    string xor_block_add(const string &block_1, const string &block_2) {
        if (block_1.length() != block_2.length()) {
            throw std::invalid_argument("Strings must have same length");
        }

        string result;
        result.reserve(block_1.length());

        // Loop through each character in the string and XOR the 
        // characters to create a new string
        for (auto i = 0; i < block_1.length(); i++) {
            result.push_back((unsigned char) block_1.at(i) ^ 
                    (unsigned char) block_2.at(i));
        }

        return result;
    }

    /* Implementation of AES 128 CBC decryption using CryptoPP's ECB decryption 
     * for each block
     */
    string aes_128_cbc_decrypt(const string &input, const string &key, 
            const string &iv) {
        auto key_ptr = (const unsigned char*) key.c_str();
        ECB_Mode<AES>::Decryption ecb_dec;
        ecb_dec.SetKey(key_ptr, key.size());

        string result;
        string xor_block = iv;

        // Loop through characters in the input using a chunk of the key size, 
        // then run an ECB decryption on that block and use the input block as 
        // the XORing block for the next iteration
        for (auto i = 0; i < input.length(); i+= key.length()) {
            try {
                string curr_in_blk = input.substr(i, key.length());
                string curr_block;
                StringSource ss(curr_in_blk, true, 
                        new StreamTransformationFilter(ecb_dec,
                            new StringSink(curr_block)
                            ) // StreamTransformationFilter
                        ); // StringSource

                string curr_dec_blk = xor_block_add(xor_block, curr_in_blk);

                // The block to chain with a xor op next iteration is the 
                // current encrypted block that was just processed
                xor_block = curr_in_blk; 

                // Add the current block to the resultant decrypted string
                result += curr_dec_blk;
            }
            catch (CryptoPP::Exception &e) {
                std::cerr << e.what() << endl;
            }
        }

        return result;
    }

    /* Uses the CryptoPP library to decrypt an input given a key and an 
     * initialization vector using AES CBC decryption. Will display an exception 
     * to stderr. Will return an empty string on error.
     */
    string aes_128_cbc_dec_cpp(const string &input, const string &key, 
            const string &iv) {
        // Check arguments
        if (input.size() == 0 || key.size() == 0 || iv.size() == 0) {
            throw std::invalid_argument("String(s) must not be empty");
        }

        string decrypted; // the decrypted string to be returned to the user

        // Using CryptoPP to perform the decryption
        try {
            CBC_Mode<AES>::Decryption cbc_decrypt;
            cbc_decrypt.SetKeyWithIV((const unsigned char*) key.c_str(), 
                    key.size(), (const unsigned char*) iv.c_str());

            StringSource ss(input, true,
                    new StreamTransformationFilter(cbc_decrypt,
                        new StringSink(decrypted)
                        ) // StreamTransformationFilter
                    ); // StringSource
        } catch (const CryptoPP::Exception &e) {
            // Display the error
            std::cerr << e.what() << endl;
        }
        return decrypted;
    }

    /* Implementation of AES 128 CBC encryption using CryptoPP's 
     * ECB decryption (already implemented ECB decryption in another 
     * function)
     */
    string aes_128_cbc_encrypt(const string &input, const string &key, 
            const string &iv) {
        // Initializing Crypto++ ECB implementation
        auto ecb_key = (const unsigned char*) key.c_str();
        ECB_Mode<AES>::Encryption ecb_encrypt;
        ecb_encrypt.SetKey(ecb_key, key.size());

        string curr_plain_block, encrypted_string;
        string curr_xor_block = iv;

        // Using ECB for each block - encrypting each plaintext block with 
        // previous encrypted block or initialization vector before 
        // feeding into ECB cipher
        for (auto i = 0; i < input.length(); i += key.length()) {
            try {
                string curr_encrypted_block;

                // XOR'ing current plaintext block against last encrypted
                // block - (starts with the initialization vector)
                string curr_input_block = xor_block_add(curr_xor_block, 
                        input.substr(i, key.length())); 

                StringSource ss(curr_input_block, true,
                        new StreamTransformationFilter(ecb_encrypt,
                            new StringSink(curr_encrypted_block) 
                            ) // StreamTransformationFilter
                        ); // StringSource ss

                curr_xor_block = curr_encrypted_block;
                encrypted_string += curr_encrypted_block;
            }
            catch (CryptoPP::Exception &e) {
                std::cerr << e.what() << endl;
            }
        }
        return encrypted_string;
    }

    /* Uses CryptoPP module to decode base64 to regular text
    */
    string base64_decode(const string &input) {
        string decoded;

        StringSource ss(input, true,
                new Base64Decoder(
                    new StringSink(decoded)
                    ) // StringSink
                ); // StringSource

        return decoded;
    }

    /* Uses CryptoPP module to encode regular text to base64
    */
    string base64_encode(const string &input) {
        string encoded;

        StringSource ss(input, true,
                new Base64Encoder(
                    new StringSink(encoded)
                    ) // StringSink
                ); // StringSource

        return encoded;
    }

    /* Prints the binary representation of each char in a string using 
     * the stdlib's bitset class
     */
    void print_string_binary(const string &input) {
        cout << endl << "String representation in binary:" << endl;

        // Looping through each char and converting to a bitset
        for (auto word : input) {
            cout << endl << std::bitset<8>(word) << " | " << (unsigned char) word << endl;
        }

        cout << endl << "End string" << endl;
    }

    // Tests to ensure that CBC encryption and decryption are consistent
    bool test_cbc(const string &input) {
        string iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"s;

        const string key = "YELLOW SUBMARINE";
        string encrypted = aes_128_cbc_encrypt(input, key, iv);
        string decrypted = aes_128_cbc_decrypt(encrypted, key, iv);
        return decrypted == input;
    }

    /* A test implementation of CryptoPP's own CBC encryption and decryption. 
     * Merely tests that the module is working and that the manner in which the 
     * code is implemented is correct
     */
    bool test_cryptopp_cbc(const string &key, const string &input) {
        string iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"s;
        string encrypted;
        string decrypted;

        // Encrypt the string
        try {
            CBC_Mode<AES>::Encryption cbc_encrypt;
            cbc_encrypt.SetKeyWithIV((const unsigned char*) key.c_str(), 
                    key.size(), (const unsigned char*) iv.c_str());

            StringSource ss(input, true, 
                    new StreamTransformationFilter(cbc_encrypt,
                        new StringSink(encrypted)
                        ) // StreamTransformationFilter
                    ); // StringSource
        } catch (const CryptoPP::Exception &e) {
            // Display the error
            std::cerr << e.what() << endl;
        }

        // Decrypt the encrypted string
        try {
            CBC_Mode<AES>::Decryption cbc_decrypt;
            cbc_decrypt.SetKeyWithIV((const unsigned char*) key.c_str(), 
                    key.size(), (const unsigned char*) iv.c_str());

            StringSource ss(encrypted, true,
                    new StreamTransformationFilter(cbc_decrypt,
                        new StringSink(decrypted)
                        ) // StreamTransformationFilter
                    ); // StringSource
        } catch (const CryptoPP::Exception &e) {
            // Display the error
            std::cerr << e.what() << endl;
        }

        // Return whether operation was successful
        return decrypted == input;
    }

    /* Challenge wrappers: functions that wrap the challenges to provide the 
     * correct output (if necessary)
     */
    string challenge_10_wrapper(const string &input_fp, const string &key, 
            const string &iv) {
        string output_parse = set_1::parse_file_to_string(input_fp);
        string b64_decoded = base64_decode(output_parse); 
        return aes_128_cbc_dec_cpp(b64_decoded, key, iv);
    }

    void test_cases() {
        cout << endl << "Set 2 test cases:" << endl << endl;

        // BEGIN TEST CASES

        /****** Challenge test cases ******/

        // Challenge 9
        cout << "\nChallenge 9:\n" << pkcs_7_padding("YELLOW SUBMARINE", 20) << endl;

        // Challenge 10
        std::string challenge_10_iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00" 
            "\x00\x00\x00\x00\x00\x00\x00"s;
        cout << "\nChallenge 10: \n" << challenge_10_wrapper("txt/challenge_10.txt"
                , "YELLOW SUBMARINE", challenge_10_iv) << endl; 

        // END TEST CASES
    }
}
