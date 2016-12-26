#include "set_2.hpp"

using std::string;
using std::cout;
using std::endl;
using namespace CryptoPP;

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

    string cbc_mode(const string &input, const string &key, const string &iv) {
        // Initializing Crypto++ ECB implementation
        const unsigned char* ecb_key = (const unsigned char*) key.c_str();
        ECB_Mode<AES>::Encryption ecb_encrypt;
        ecb_encrypt.SetKey(ecb_key, key.size());

        string curr_plain_block, curr_encrypted_block, cbc_result;
        string curr_xor_block = iv;
        
        // Using ECB for each block - encrypting each plaintext block with 
        // previous encrypted block or initialization vector before 
        // feeding into ECB cipher
        for (auto i = 0; i < input.length(); i += key.length()) {
            try {
                // XOR'ing current plaintext block against last encrypted
                // block - (starts with the initialization vector)
                curr_plain_block = set_1::rep_xor_encrypt(curr_xor_block, 
                        input.substr(i, key.length()));

                StringSource ss(curr_plain_block, true,
                        new StreamTransformationFilter(ecb_encrypt,
                            new StringSink(curr_encrypted_block
                                ) // StringSink
                            ) // StreamTransformationFilter
                        ); // StringSource ss

                curr_xor_block = curr_encrypted_block;
                cbc_result += curr_encrypted_block;

                cout << curr_encrypted_block;

                curr_encrypted_block.clear();
                curr_encrypted_block.reserve(key.length());
            }

            catch (CryptoPP::Exception &e) {
                std::cerr << e.what() << endl;
                exit(1);
            }
        }

        return cbc_result;
    }

    // Challenge wrappers: functions that wrap the challenges to provide the 
    // correct output (if necessary)
    // TODO challenge 10
    string challenge_10_wrapper(const string &input_fp, const string &key, 
            const string &iv) {
        string input_parse = set_1::parse_file_to_string(input_fp);

        return cbc_mode(input_parse, key, iv);
    }

    void test_cases() {
        cout << endl << "Set 2 test cases:" << endl << endl;

        // BEGIN TEST CASES

        cout << "Challenge 9: " << pkcs_7_padding("YELLOW SUBMARINE", 20) << endl;
        
        cout << "Challenge 10: " << challenge_10_wrapper("txt/challenge_10.txt"
                , "YELLOW SUBMARINE", "\x00") << endl;

        // END TEST CASES
    }
}
