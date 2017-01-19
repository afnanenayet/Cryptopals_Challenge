#include "set_2.hpp"

using std::string;
using std::cout;
using std::endl;
using namespace CryptoPP;
using namespace std::literals::string_literals;

namespace set_2 {
    // Computes the number of bytes to add to the string, converts that 
    // number to a string, then adds it repeatedly to the 
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

    string xor_block_add(const string &block_1, const string &block_2) {
        if (block_1.length() != block_2.length()) {
            throw std::invalid_argument("Strings must have same length");
        }

        string result;
        result.reserve(block_1.length());

        for (auto i = 0; i < block_1.length(); i++) {
            result.push_back((unsigned char) block_1.at(i) ^ 
                    (unsigned char) block_2.at(i));
        }

        return result;
    }

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
                exit(1);
            }
        }

        return encrypted_string;
    }

    string aes_128_cbc_decrypt(const string &input, const string &key, 
            const string &iv) {
        auto ecb_key = (const unsigned char*) key.c_str();
        ECB_Mode<AES>::Decryption ecb_decrypt;
        ecb_decrypt.SetKey(ecb_key, key.size());
        string decrypted_string;
        string xor_block = iv;

        // decrypt each block with ECB then XORs with the xor_block
        // updates xor block to be the last encrypted block
        for (auto i = 0; i < input.length(); i += key.length()) {
            try {
                string curr_decrypt_blk;
                string curr_input_block = input.substr(i, key.length());

                // CryptoPP ECB decryption
                StringSource ss(curr_input_block, true,
                        new StreamTransformationFilter(ecb_decrypt,
                            new StringSink(curr_decrypt_blk) 
                            ) // StreamTransformationFilter
                        ); // StringSource ss

                // XORing the string with xor block/IV for final output
                decrypted_string += xor_block_add(curr_decrypt_blk, xor_block);

                // xor block is the encrypted block that we just decrypted
                xor_block = curr_input_block;
            }

            catch (CryptoPP::Exception &e) {
                std::cerr << e.what() << endl;
                exit(1);
            }
        }

        return decrypted_string;
    }

    // Challenge wrappers: functions that wrap the challenges to provide the 
    // correct output (if necessary)
    // TODO challenge 10
    string challenge_10_wrapper(const string &input_fp, const string &key, 
            const string &iv) {
        string input_parse = set_1::parse_file_to_string(input_fp);
        auto b64_decode_vec = base64::decode(input_parse);

        return aes_128_cbc_decrypt(string(b64_decode_vec.begin(),
                    b64_decode_vec.end()), key, iv);
       //  return aes_128_cbc_decrypt(input_parse, key, iv);
    }

    void test_cases() {
        cout << endl << "Set 2 test cases:" << endl << endl;

        // BEGIN TEST CASES

        cout << "Challenge 9: " << pkcs_7_padding("YELLOW SUBMARINE", 20) << endl;

        std::string challenge_10_iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00" 
            "\x00\x00\x00\x00\x00\x00\x00"s;
        cout << "Challenge 10: " << challenge_10_wrapper("txt/challenge_10.txt"
                , "YELLOW SUBMARINE", challenge_10_iv) << endl;

        /*auto encryption_test = aes_128_cbc_encrypt(
         * pkcs_7_padding("YELLOW SUBMARINE", 16), "YELLOW SUBMARINE", challenge_10_iv);
        cout << aes_128_cbc_decrypt(encryption_test, "YELLOW SUBMARINE", challenge_10_iv);
        */

        // END TEST CASES
    }
}
