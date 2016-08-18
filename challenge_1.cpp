#include <string>
#include <bitset>
#include <iostream>
#include <queue>

namespace crypto {
	// Converts a hex encoded string to a base64 encoded string
	// with bit level manipulations

	// Converts a hex char to a decimal representation
	// cast as a char
	inline char hex_to_decimal(char hex_char) {
		// Getting the index of the character offset
		// WARNING: the character ranges may NOT be consecutive
		// depending on the encoding used (should work in
		// UTF-8 and ASCII)
		if ('0' <= hex_char && hex_char <= '9') {
			return hex_char - '0';
		}
		else if ('A' <= hex_char && hex_char <= 'F') {
			return (hex_char - 'A') + 0xA;
		}
		else if ('a' <= hex_char && hex_char <= 'f') {
			return (hex_char - 'a') + 0xA;
		}
		else {
			throw - 1;
		}
	}

	std::string hex_to_base64(std::string hex_string) {
		const std::string base64_cipher =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
		const size_t array_length = 4;
		std::string base64_string;
		base64_string.reserve((hex_string.length() * 4) / 6);

		auto valid_words = 1;

		// Turning three hex letters into a 24 bit number then
		// dividing up into 4 base64 characters (6 bits each)
		// 24 is evenly divisible by 8 (size of a char), 4 (size
		// of a hex word), and 6 (size of a base64 word)
		for (int i = 0; i < hex_string.length(); i += 3) {
			unsigned char base64_words[array_length];

			// using '=' as null indicator as 0 is a valid
			// base64 index
			std::fill_n(base64_words, array_length, '=');

			int hex_word_b =
				crypto::hex_to_decimal(hex_string.at(i)) << 16;

			// Checking to see if there are any words afterwards,
			// if not, then pad with 0's
			if (i + 1 < hex_string.length()) {
				hex_word_b +=
					crypto::hex_to_decimal(hex_string.at(i + 1)) << 8;
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
			for (int n = 0; n < ((valid_words * 8) / 6) + 1; n++) {
				unsigned char current_char = hex_word_b >> (6 * n) & 0b111111;
				base64_words[n] = current_char;
			}

			// Converting each unpacked 6 bit word to the corresponding
			// base64 character
			for (auto character : base64_words) {
				base64_string.push_back(base64_cipher.at(character));
			}
		}
		return base64_string;
	}
}

using namespace std;
int main() {
	cout << crypto::hex_to_base64("13f") << "\n";
	// should be "ERER"
	system("PAUSE");
	return 0;
}