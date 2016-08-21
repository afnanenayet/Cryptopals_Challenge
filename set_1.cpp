#include "set_1.hpp"

namespace set_1 {
	inline unsigned char hex_decode(unsigned char hex_char) {
		// Getting the index of the character offset
		// WARNING: the character ranges may NOT be consecutive
		// depending on the encoding used (should work in
		// UTF-8 and ASCII)
		if ('0' <= hex_char && hex_char <= '9') {
			return (hex_char - '0');
		}

		else if ('A' <= hex_char && hex_char <= 'F') {
			return (hex_char - 'A') + 0xA;
		}

		else if ('a' <= hex_char && hex_char <= 'f') {
			return (hex_char - 'a') + 0xA;
		}

		else {
			throw std::invalid_argument("Received a character that is not a valid hexadecimal unsigned char.");
		}
	}

    inline unsigned char hex_encode(unsigned char dec_char) {
        if (0x0 <= dec_char && dec_char <= 0x9) {
            return '0' + dec_char;
        }

        else if (0xA <= dec_char && dec_char <= 0xF) {
            return 'a' + (dec_char - 0xA);
        }

        else {
            throw std::invalid_argument("Received a number that is not between 0 and 16.");
        }
    }

	std::string hex_to_base64(const std::string &hex_string) {
		const std::string base64_cipher =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
		const size_t array_length = 2;
		std::string base64_string;

        // 4 bits / 6 bits reduces to 2 / 3
        // (reserves space for # of characters)
		base64_string.reserve((hex_string.length() * 2) / 3);
        
		auto valid_words = 1;

		// Turning three hex letters into a 12 bit number then
		// dividing up into 2 base64 characters (6 bits each)
		// 12 is evenly divisible by 4 (size
		// of a hex word), and 6 (size of a base64 word)
		for (int i = 0; i < hex_string.length(); i += 3) {
			int hex_word_b =
				set_1::hex_decode(hex_string.at(i)) << 8;

			// Checking to see if there are any words afterwards,
			// if not, then pad with ='s
			if (i + 1 < hex_string.length()) {
				hex_word_b +=
					set_1::hex_decode(hex_string.at(i + 1)) << 4;
				valid_words += 1;
			}

			if (i + 2 < hex_string.length()) {
				hex_word_b +=
					set_1::hex_decode(hex_string.at(i + 2));
				valid_words += 1;
			}
            
			// Unpacking into four base64 words
			// and masking first 6 bits
			// and shifting as necessary
			for (int n = (valid_words * 4 > 6) ? 2 : 1; n > 0; n--) {
                base64_string.push_back(base64_cipher
				.at(hex_word_b >> (6 * (n - 1)) & 0b111111));
			}
        }

        // Adding = padding for base64 string
        // Base64 can only guarantee even measuring in three byte bundles
        for (int i = 0; i < ((hex_string.length() * 4) / 8) % 3; i++) {
            base64_string.push_back('=');
        }
		return base64_string;
	}

    std::string hex_xor_op(const std::string &hex_string_1, const std::string &hex_string_2) {
       if (hex_string_1.length() != hex_string_2.length()) {
           throw std::invalid_argument("The string buffers must be the same length.");
       }

       else {
           std::string xor_result_string;
           xor_result_string.reserve(hex_string_1.length());
           
           // Iterating through both strings and getting xor combination of their chars
           // then converting char back to hex encoding and pushing to result string
           for (int i = 0; i < hex_string_1.length(); i++) {
               auto hex_1_char = set_1::hex_decode(hex_string_1.at(i));
               auto hex_2_char = set_1::hex_decode(hex_string_2.at(i));
               unsigned char resultant_char = hex_1_char ^ hex_2_char;
               xor_result_string.push_back(set_1::hex_encode(resultant_char));
           }
           return xor_result_string;
       }
    }

    std::string single_xor_decrypt(const std::string &xor_encoded_string) {
        // The 12 most used characters in the English language
        // - used to score the decoded text
        const std::string scoring_key = "ETAOINSHRLDU";
        
        unsigned char current_max_key = 0x0;
        int current_max_score = 0;

        // testing each hex character, decoding, then scoring
        // resultant output string against scoring key
        for (unsigned char i = 0x0; i <= 0xf; i++) {
            // XOR'ing the string against a hex character
            std::string char_string;
            char_string.push_back(set_1::hex_encode(i));
            std::string testing_string = set_1::hex_xor_op(xor_encoded_string, char_string);
            std::string decoded_text_string;
            decoded_text_string.reserve(testing_string.length() / 2);

            // Converting the resultant string to normal chars
            // by combining two 4-bit hex chars into 1 8 bit char
            for (int n = 0; n < testing_string.length(); n+=2) {
                unsigned char hex_to_char = testing_string.at(n) << 4;

                if (n + 1 < testing_string.length()) {
                    hex_to_char |= testing_string.at(n + 1);
                }

                decoded_text_string.push_back(hex_to_char);
            }

            // Getting score for this XOR'd string
            // TODO: find instances of each letter for string, add to score
            // TODO: then get key for max score, then decode and return decoded string
        }
        return "hello!";
    }
    
    void test_cases() {
        // Output of 0 indicates successful test case. Any other number indicates failure.
        std::cout << "Challenge 1: " << set_1::hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
        .compare("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t") << "\n";
        std::cout << "Challenge 2: " << (set_1::hex_xor_op("1c0111001f010100061a024b53535009181c",
                                                           "686974207468652062756c6c277320657965")
                                         .compare("746865206b696420646f6e277420706c6179"))<< "\n";
        
        std::cout << "\n";
    }
}


