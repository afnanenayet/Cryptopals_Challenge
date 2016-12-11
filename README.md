# Matasano Cryptopals Challenge Solutions
This is an ongoing attempt to solve the Matasano Cryptopals Challenge in C++. 
The challenges are taken from here: http://www.cryptopals.com

## Acknowledgements
I used the cppcodec library, found here: https://github.com/tplgy/cppcodec with my solutions.

## Building the solutions
First, clone the repo. (In terminal): `git clone https://github.com/afnanenayet/Cryptopals_Challenge.git`

Then to build the binary: `cmake . && make`

If you want to edit in Vim, you may want to run `ctags -R . && make tags`

To run the executable: `./Cryptopals_Challenge`

I personally built this using a compiler that supports C++14. I think it should work with C++11 but I haven't tested it.
