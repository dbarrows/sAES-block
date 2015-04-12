Simple AES block encryption
==============================

Implements a both a CTR-based and CBC-based Simple AES (sAES) block encryption algorithm.


CBC-sAES options
--------------------

Command line arguments (must be in order):

|Argument|Description|
|--------|-----------|
|-e / -d | Tells the program to encrypt or decrypt |
|input file name | Name of the file containing the plaintext or ciphertext |
|key | Key to use |
|output file name | Name of the file to put the ciphertext or plaintext |
|padding length	| Amount of padding that was used to encrypt the data, only for decryption mode (optional) |
|nonce | Nonce seed to use to generate the IV (optional) |

Note that input less than 16-bits (a single block) will simply be padded with 0s as ciphertext stealing is not possible



CTR-sAES options
----------------------------------------------------------------

Command line arguments (must be in order):

|Argument|Description|
|--------|-----------|
|-e / -d | Tells the program to encrypt or decrypt |
|input file name | Name of the file containing the plaintext or ciphertext |
|key | Key to use |
|output file name | Name of the file to put the ciphertext or plaintext |
|nonce | Nonce seed to use to generate the IV |


Examples:
---------

**CBC-sAES**

Encryption

	$ ./CBC-sAES -e infile2 1234 outfile2 0 34
	Set to encrypt.
	File data:		110010011010111110
	Multiple blocks with last block that is 14-bit(s) short detected, ciphertext stealing will be used.
	Key:			0x1234
	Padded data:	11001001101011111000000000000000
	IV:				0x2218
	Ciphertext:		0xC9AF8000
	Plaintext:		0xB1CF3EEC

Decryption

	$ ./CBC-sAES -d outfile2 1234 in_prime2 14 34
	Set to decrypt.
	File data:		110010011010111110
	Key:			0x1234
	Padded data:	11001001101011111000000000000000
	IV:				0x2218
	Plaintext:		0xB1CF3EEC
	Ciphertext:		0xC9AF8000

Then running

	$ cat infile2 in_prime2
	110010011010111110
	110010011010111110

shows that encryption/decryption was successful, and that the padded data was successfully removed after decryption.

Also:

	$ cat outfile2
	10110001110011110011111011101100

shows that the ciphertext is padded as it is supposed to be.

**CTR-sAES**

Encryption

	$ ./CTR-sAES -e infile2 34f1 outfile2 56
	Set to encrypt.
	File data:		110010011010111110
	Multiple blocks with last block that is 14-bit(s) short detected.
	Key:			0x34F1
	Padded data:	11001001101011111000000000000000
	CTR seed:		0x77C4
	Plaintext:		0xC9AF8000
	Ciphertext:		0x73532389

Decryption

	$ ./CTR-sAES -d outfile2 34f1 in_prime2 56
	Set to decrypt.
	File data:		011100110101001100
	Multiple blocks with last block that is 14-bit(s) short detected.
	Key:			0x34F1
	Padded data:	01110011010100110000000000000000
	CTR seed:		0x77C4
	Ciphertext:		0x73530000
	Plaintext:		0xC9AF8000

Then running

	$ cat infile2 in_prime2
	110010011010111110
	110010011010111110

shows that encryption/decryption was successful, and that the padded data was successfully removed after decryption.

Also

	$ cat outfile2
	011100110101001100

shows that the ciphertext is *not* padded, as should be the case.