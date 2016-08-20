#include <string>
#include <bitset>
#include <iostream>
#include <queue>
#include <stdexcept>

namespace crypto {
	// Converts a hex char to a decimal representation
	// cast as an unsigned char
	inline unsigned char hex_to_decimal(unsigned char hex_char) {
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
			throw std::invalid_argument("Received a character that is not a valid hexadecimal unsigned char");
		}
	}

	std::string hex_to_base64(const std::string &hex_string) {
		const std::string base64_cipher =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
		const size_t array_length = 2;
		std::string base64_string;

        // 4 bytes / 6 bytes reduces to 2 / 3
		base64_string.reserve((hex_string.length() * 2) / 3);
        
		auto valid_words = 1;

		// Turning three hex letters into a 12 bit number then
		// dividing up into 2 base64 characters (6 bits each)
		// 12 is evenly divisible by 4 (size
		// of a hex word), and 6 (size of a base64 word)
		for (int i = 0; i < hex_string.length(); i += 3) {
			int hex_word_b =
				crypto::hex_to_decimal(hex_string.at(i)) << 8;

			// Checking to see if there are any words afterwards,
			// if not, then pad with ='s
			if (i + 1 < hex_string.length()) {
				hex_word_b +=
					crypto::hex_to_decimal(hex_string.at(i + 1)) << 4;
				valid_words += 1;
			}

			if (i + 2 < hex_string.length()) {
				hex_word_b +=
					crypto::hex_to_decimal(hex_string.at(i + 2));
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
}

using namespace std;
int main() {
	cout << crypto::hex_to_base64("12") << "\n";
    // Correct hex conversion is: ""
	return 0;
}
