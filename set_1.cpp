#include "set_1.hpp"

using std::cout;
namespace set_1 {
    // Combines two hex characters to an 8 bit ASCII character
    inline std::string hex_to_text(const std::string &hex_string) {
        std::string decoded_text_string;
        
        // A char is 8 bits, a hex character takes 4 bits
        // thus we cram two hex characters to form one normal
        // ASCII char
        decoded_text_string.reserve(hex_string.length() / 2);

        // Converting the resultant string to normal chars
        // by combining two 4-bit hex chars into 1 8 bit char
        for (int n = 0; n < hex_string.length(); n+=2) {
            unsigned char hex_to_char = (hex_string.at(n) << 4) & 0b11110000;

            if (n + 1 < hex_string.length()) {
                hex_to_char |= (set_1::hex_decode(hex_string.at(n + 1)) &
                    0b1111);
            }
            decoded_text_string.push_back(hex_to_char);
        } 
    
        return decoded_text_string;
    }

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

    // Getting index offsets for each hex character
    // WARNING: this function only works if the encoding
    // places chars '0' - '9' and 'a' - 'f' adjacent to
    // each other in the encoding
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

    // Cycling through chars of a plaintext string, splitting into two hex
    // chars
    inline std::string hex_encode_str(const std::string &plaintext_string) {
        std::string hex_string;

        for (unsigned char letter : plaintext_string) {
            // Splitting char into the first 4 bits and last 4 bits
            hex_string.push_back(hex_encode((letter & 0b11110000) >> 4));
            hex_string.push_back(hex_encode(letter & 0b1111));
        }

        return hex_string;
    }

	std::string hex_to_base64(const std::string &hex_string) {
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
				hex_decode(hex_string.at(i)) << 8;

			// Checking to see if there are any words afterwards,
			// if not, then pad with ='s
			if (i + 1 < hex_string.length()) {
				hex_word_b +=
					hex_decode(hex_string.at(i + 1)) << 4;
				valid_words += 1;
			}

			if (i + 2 < hex_string.length()) {
				hex_word_b +=
					hex_decode(hex_string.at(i + 2));
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

    // Uses the hex_decode function to convert each character for each 
    // string to binary then runs a xor operation across the chars, 
    // then encodes the xor'd string back to hex
    std::string hex_xor_op(const std::string &hex_string_1, const std::string
        &hex_string_2) {

       if (hex_string_1.length() != hex_string_2.length()) {
           throw std::invalid_argument("The string buffers must be the same length.");
       }

       else {
           std::string xor_result_string;
           xor_result_string.reserve(hex_string_1.length());
           
           // Iterating through both strings and getting xor combination of 
           // their chars then converting char back to hex encoding and 
           // pushing to result string
           for (int i = 0; i < hex_string_1.length(); i++) {
               auto hex_1_char = hex_decode(hex_string_1.at(i));
               auto hex_2_char = hex_decode(hex_string_2.at(i));
               unsigned char resultant_char = hex_1_char ^ hex_2_char;
               xor_result_string.push_back(hex_encode(resultant_char));
           }

           return xor_result_string;
       }
    }

    // Decodes the hex string to binary, runs a xor operation for each
    // character against a given key, then encodes the result in hex
    std::string xor_op_sk(const std::string &xor_string, 
        unsigned char xor_key) {

        std::string xor_result_string;
        xor_result_string.reserve(xor_string.length());
        
        // Iterating through string and getting xor combo against hey_key
        for (unsigned char letter : xor_string) {
            unsigned char resultant_char = letter ^ xor_key;
            xor_result_string.push_back(resultant_char);
        }

        return xor_result_string;
    }

    // Iterating through each possible char value, decoding the hex string
    // then xor'ing it against the key. Looking for best possible match via
    // frequency analysis
    std::string single_xor_decrypt(const std::string &xor_encoded_string) {
        unsigned char current_min_key = 0x0;
        double current_min_score = std::numeric_limits<double>::max();

        // testing each hex character, decoding, then scoring
        // resultant output string against scoring key
        for (unsigned char i = 0; i < UCHAR_MAX; i++) {
            // XOR'ing the string against a hex character
            std::string testing_string = xor_op_sk(hex_to_text
                (xor_encoded_string), i);
            double alpha_score = alpha_ranking(testing_string);
            double freqa_score = freqa_ranking(testing_string);
            auto current_score = (freqa_score * .6) - (alpha_score * .4);

            // Updating max/min if necessary
            if (current_score < current_min_score) {
                current_min_score = current_score;
                current_min_key = i;
            }
        }
        // Returning the decoded text from the encoded string using
        // the key ascertained above
        return xor_op_sk(hex_to_text(xor_encoded_string), current_min_key);
    }

    // Iterating through each possible char value, decoding the hex string
    // then xor'ing it against the key. Looking for best possible match via
    // frequency analysis
    unsigned char single_xor_decrypt_key(const std::string 
        &xor_encoded_string) {

        unsigned char current_min_key = 0x0;
        double current_min_score = std::numeric_limits<double>::max();

        // testing each hex character, decoding, then scoring
        // resultant output string against scoring key
        for (unsigned char i = 0; i < UCHAR_MAX; i++) {
            // XOR'ing the string against a hex character
            std::string reverse_encoded_str = xor_op_sk(xor_encoded_string, i);

            // TODO REMOVE DEBUG
            // cout << "\nxor encoded string: " << reverse_encoded_str << "\n";

            double alpha_score = alpha_ranking(xor_encoded_string);
            double freqa_score = freqa_ranking(xor_encoded_string);
            auto current_score = (freqa_score * .6) - (alpha_score * .4);

            // Updating max/min if necessary
            if (current_score < current_min_score) {
                
                // TODO REMOVE DEBUG
                cout << "\nNew score: " << current_score << "\n";

                current_min_score = current_score;
                current_min_key = i;
                cout << "Bitset for key: " << std::bitset<8>(current_min_key) << "\n";
            }
        }

        return current_min_key;
    }
    
    // Takes the string, analyzes the distribution of letters in the string
    // Compares those letters to the frequency of the most popular letters in
    // the English language, then uses the distance formula to calculate how
    // far off the string is from average English
    double freqa_ranking(std::string english_string) {
        // Converting all the letters to lower case for the comparison
        std::transform(english_string.begin(), english_string.end(), 
            english_string.begin(), ::tolower);

        // The distribution of the top 12 letters in the English language
        const std::map<char, double> english_fr_dist = {{'e', .12702}, 
            {'t', .09056}, {'a', .08167}, {'o', .07507}, {'i', .06966},
            {'n', .06749}, {'s', .06327}, {'h', .06094}, {'r', .05987},
            {'l', .04025}, {'d', .04253}, {'u', .02759}};

        // Error from normal distribution for given letters in the string
        std::map<char, double> string_fr_dist;

        // Sum of the squares of the differences for the distance formula
        double radicand = 0;

        // Looping through each key in the english_fr_dist map and getting
        // ratio of each character in the given string and adding to the
        // radicand
        for (auto& map_elem : english_fr_dist) {

            // observed ratio of letters in string
            double ratio = (static_cast<double>(std::count(english_string
                .begin(), english_string.end(), map_elem.first))) / 
                (static_cast<double>(english_string.length()));

            radicand += pow((ratio - map_elem.second), 2);
        }

        return sqrt(radicand);
    }

    double alpha_ranking(const std::string & alpha_string) {
        double alpha_score = 0;
        // Getting ratio of characters that are alphabetical
        for (char letter : alpha_string) {
             if (std::isalpha(letter) != 0) {
                 alpha_score++;
             }
        }

         // Ignoring spaces in the alphabetical ranking
         alpha_score /= alpha_string.length() 
             - std::count(alpha_string.begin(), alpha_string.end(), ' ');
         return alpha_score;
    }

    // Iterates through each line in the given file, then computes
    // the most likely decoded string for each hex encoded string
    // and finally returns the most likely comprehensible English
    // string of all the decoded strings
    std::string detect_schar_xor(const std::string &file_name) {
        std::ifstream string_file(file_name, std::ios_base::in);
        std::string curr_line;
        
        // The string that is most likely to be the xor decrypted string
        // based on frequency and alphabetical analysis
        std::string curr_top_line;

        double current_min_score = std::numeric_limits<double>::max();

        // Looping through each line in the file
        while (string_file >> curr_line) {
            // Getting line, then running a frequency analysis
            // then finding what prop. is alphabetical
            // then computing a score (lower is better)
            auto curr_decoded_str = single_xor_decrypt(curr_line);
            auto freqa_score = freqa_ranking(curr_decoded_str);
            auto alpha_score = alpha_ranking(curr_decoded_str);
            double current_score = (freqa_score * .6) - (alpha_score * .4);

            if (current_score < current_min_score) {
                current_min_score = current_score;
                curr_top_line = curr_decoded_str;
            }
        }

        string_file.close();
        return curr_top_line;
    }

    // XOR's a string against each character of a key, using modulus 
    // arithmetic to cycle through the key
    std::string rep_xor_encrypt(const std::string &key, const std::string 
        &message) {

        std::string encrypted_message;
        encrypted_message.reserve(message.length());

        // Performing a XOR op for every character in the message string
        for (int i = 0; i < message.length(); i++) {
            encrypted_message.push_back(message.at(i) ^ (key.at
                (i % key.length())));
        }

        return encrypted_message;
    }

    // Iterates through possible key sizes and brute forces combinations
    // until most likely key size is found
    unsigned int xor_key_size_bf(const std::string &xor_encoded_string, 
        const unsigned int &key_lower_limit, const unsigned int 
        &key_upper_limit, const unsigned int &num_pairs) {

        unsigned int est_key_size = 0;
        float lowest_edit_dist = 1000;
        
        // Iterating through difference key sizes and trying to find the most
        // likely key size
        for (auto curr_key_size = key_lower_limit; curr_key_size <= 
        key_upper_limit; curr_key_size++) {
            std::vector<float> hamming_distances(num_pairs);

            // Finding edit distance, normalizing by key size, and finding min
            // to estimate key size
            for (int n = 0; n < 2 * num_pairs && (n + 2) * curr_key_size < 
            xor_encoded_string.length(); n += 2) {
                float n_hamming_dist = hamming_distance(xor_encoded_string
                    .substr(n * curr_key_size, curr_key_size),
                xor_encoded_string.substr((n + 1) * curr_key_size, 
                    curr_key_size));
                n_hamming_dist /= curr_key_size;
                hamming_distances.push_back(n_hamming_dist);
            }

            // Getting average of hamming distances
            auto avg_ham_dist = std::accumulate(hamming_distances.begin(), 
                hamming_distances.end(), 0) / hamming_distances.size();

            // Setting min
            if (avg_ham_dist < lowest_edit_dist) {
                lowest_edit_dist = avg_ham_dist;
                est_key_size = curr_key_size;
            }
        }
        return est_key_size;
    }

    // TODO: FINISH
    std::string rep_xor_decrypt(const std::string &file_name, const unsigned
        int key_lower_limit, const unsigned int key_upper_limit) {

        std::ifstream base64_file(file_name, std::ios_base::in);

        if (base64_file.is_open()) {
            std::string est_key;
            std::stringstream file_buf;

            // Outputting contents of file to string
            file_buf << base64_file.rdbuf();
            auto decoded_string = base64_decode(file_buf.str());

            // Brute-forcing the key size
            auto key_size = xor_key_size_bf(decoded_string, key_lower_limit,
            key_upper_limit, 2);

            // Reserving space for vectors
            std::vector<std::string> text_blocks;
            std::vector<std::string> transposed_text_blocks(key_size);

            // Breaking up text into blocks of estimated key size length
            for (int i = 0; i + key_size < decoded_string.length();
                i += key_size) {

                std::string text_block;
                text_block.reserve(key_size);

                for (int n = 0; n < key_size; n++) {
                    text_block.push_back(decoded_string.at(n + i));
                }

                text_blocks.push_back(text_block);
            }
 
            // Transposing text blocks to place matching key chars together
            // nth char of each block pushed to nth index of the transposed
            // block vector
            for (int i = 0; i < text_blocks.size(); i++) {
                for (int n = 0; n < text_blocks.at(i).length(); n++) {
                    // Pushing back nth element of the block to nth index in 
                    // the transposed vector
                    (transposed_text_blocks.at(n)).push_back(text_blocks
                    .at(i).at(n));
                }
            }

            for (std::string block : transposed_text_blocks) {
                // decrypt each xor encrypted string here;
                est_key.push_back(single_xor_decrypt_key(block));
            }

            // TODO REMOVE DEBUG
            cout << "\nEstimated key length: " << est_key.length() << "\n";
            cout << "Decoded string: " << decoded_string << "\n";
            cout << "\nEstimated key: " << est_key << "\n";

            base64_file.close();  
            return rep_xor_encrypt(est_key, decoded_string);
        }

        else {
            throw std::invalid_argument("Unable to open file" 
                                        "specified by file name.");
        }
    }

    // Uses the standard bitset Hamming weight method to calculate the 
    // differing number of bits
    unsigned int hamming_distance(const std::string &string_1, 
        const std::string &string_2) {
        unsigned int bit_count = 0;

        for (int i = 0; i < string_1.length() && i < string_2.length(); i++) {
            // Getting the differing bits
            unsigned char nand_op_result = string_1.at(i) ^ string_2.at(i); 
            
            // Getting Hamming weight via standard op w/ bitset
            bit_count += std::bitset<8>(nand_op_result).count();
        }

        return bit_count;
    }

    // Output of 0 indicates successful test case. Any other number indicates failure.
    // There are some exceptions where success is indicated by the output of
    // Vanilla Ice lyrics
    void test_cases() {
        std::cout << "\nSet 1 test cases:\n\n";
        
        // BEGIN TEST CASES

        std::cout << "Challenge 1: " << hex_to_base64("49276d206b696c6c696e6720796f757220627261696"
        "e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
        .compare("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t") << "\n";
        std::cout << "Challenge 2: " << (hex_xor_op("1c0111001f010100061a024b53535009181c",
                                                           "686974207468652062756c6c277320657965")
                                         .compare("746865206b696420646f6e277420706c6179"))<< "\n";
        
        std::cout << "Challenge 3: " << single_xor_decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736") << "\n";
        std::cout << "Challenge 4: " << detect_schar_xor("xor_strings.txt");
        std::cout << "Challenge 5: " << hex_encode_str(rep_xor_encrypt("ICE", "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")).compare("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f") << "\n";
        std::cout << "Hamming distance: " << hamming_distance("this is a test", "wokka wokka!!!") << "\n";
        std::cout << "Challenge 6: " << rep_xor_decrypt("challenge_6.txt", 2, 40);

        // END TEST CASES
        std::cout << "\n";
    }
}
