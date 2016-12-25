#include "set_2.hpp"

using std::string;
using std::cout;
using std::endl;

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

    void test_cases() {
        cout << endl << "Set 2 test cases:" << endl << endl;

        // BEGIN TEST CASES

        cout << "Challenge 9: " << pkcs_7_padding("YELLOW SUBMARINE", 20) << endl;

        // END TEST CASES
    }
}
