// Author:  Dexter Barrows


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <math.h>

typedef unsigned char byte;
typedef uint16_t word;

int poly_degree(byte poly);
byte gf_reduce_4(byte poly);
byte gf_mult_4(byte poly1, byte poly2);
void print_byte(byte out);
byte convert_char_to_hex(char raw_input);
byte rotate_byte(byte input);
byte s_box_4(byte input);
byte s_box_8(byte input);
byte inv_s_box_4(byte input);
byte inv_s_box_8(byte input);
byte * generate_keys(byte* key);
word encrypt_word(word input, byte* key);
word decrypt_word(word input, byte* key);
word add_key(word input, word key);
word n_substitution(word input);
word inv_n_substitution(word input);
word shift_row(word input);
word mix_column(word input);
word inv_mix_column(word input);
void print_key(byte* keys);
byte bit_string_to_byte(char* bitstring);
char* byte_to_bit_string(byte input);
word generate_IV_from_nonce(int nonce, byte* key);

int main(int argc, char *argv[]) {

    int encrypt_flag    = 0;
    int decrypt_flag    = 0;

    if(argc < 6) {
        printf("Too few options. Program terminating...\n");
        exit(1);
    }

    //determine operation type (encryption/decryption) and set flags accordingly
    char * op_type = argv[1];
    if( strcmp(op_type, "-e") == 0) {
        encrypt_flag = 1;
        printf("Set to encrypt.\n");
    }
    else if( strcmp(op_type, "-d") == 0) {
        decrypt_flag = 1;
        printf("Set to decrypt.\n");
    }
    else {
        printf("Invalid option. Program terminating...\n");
        exit(1);
    }

    //set up variables for reading from input file and check for errors
    char * infile = argv[2];
    FILE * ifp = fopen(infile, "r");
    char * line = (char*)malloc(100*sizeof(char));
    int    max_data = 100; //max number of chars to encrypt/decrypt
    if (ifp == NULL) {
    	printf("Cannot open input file, or file does not exist. Exiting...\n");
       	exit(1);
    }

    //read data from file and check for errors, then close
    if ( fgets ( line, 100, ifp ) == NULL ) {
        printf("Cannot read from input file. Exiting...\n");
        exit(1);
    } else
        printf("File data:\t%s", line);
    fclose(ifp);

    //get and check data size
    int multi_flag  = 0;
    int mis_bits    = 0;
    int data_size = strlen(line) - 1;
    float num_blocks_dec = ((float) data_size) / 16.0;
    int num_blocks = ceil ( num_blocks_dec );
    if(data_size < 16) {
        mis_bits = 16 - data_size;
        printf("Single block that is %d-bit(s) short detected,\nplaintext will be padded with %dx 0 at end.\n", mis_bits, mis_bits);
    } else if (data_size > 16) {
        multi_flag = 1;
        if( num_blocks > num_blocks_dec ) {
            mis_bits = num_blocks*16 - data_size;
            printf("Multiple blocks with last block that is %d-bit(s) short detected.\n", mis_bits);
        }
    }

    int i,j;

    //parse key data and set up byte array, display key
    char* key_string = argv[3];
    byte * key = (byte*)malloc(4*sizeof(byte));
    for(i = 0; i < 4; i++)
        key[i] = convert_char_to_hex(key_string[i]);
    word key_w = 0x0;
    for(i = 0; i < 4; i++)
    	key_w += (key[i] << (4*(3-i)));
    printf("Key:\t\t0x%04X\n", key_w);

    //pad data if necessary
    if(mis_bits) {
        line = realloc(line, (16*num_blocks+1)*sizeof(char));
        for(i = (16*num_blocks - mis_bits); i < 16*num_blocks; i++)
            line[i] = '0';
        line[16*num_blocks] = '\0';
        printf("Padded data:\t%s\n", line);
    }

    //block data into words
    word data[num_blocks];
    for(i = 0; i < num_blocks; i++) {                               //per word
        char* left_string = (char*)malloc(9*sizeof(char));
        char* right_string = (char*)malloc(9*sizeof(char));
        for(j = 0; j < 8; j++) {                                    //per byte
            left_string[j] = line[j+16*i];
            right_string[j] = line[j+16*i+8];
        }
        left_string[8] = '\0';
        right_string[8] = '\0';
        byte left = bit_string_to_byte(left_string);
        byte right = bit_string_to_byte(right_string);
        data[i] = (left << 8) + right;
    }
    
    //get IV if there is a user-provided nonce
    int nonce = atoi(argv[5]);
    word IV = generate_IV_from_nonce(nonce, key);
    printf("CTR seed:\t0x%04X\n", IV);

    //generate CTR values from IV
    word CTR[num_blocks];
    CTR[0] = generate_IV_from_nonce(IV, key);
    for(i = 1; i < num_blocks; i++) {
        CTR[i] = generate_IV_from_nonce(CTR[i-1],key);
    }

    //array to hold output
    word output[num_blocks];

    //encrypt or decrypt
    if (encrypt_flag) {

        printf("Plaintext:\t0x");                                   //display input data
        for(i = 0; i < num_blocks; i++)
            printf("%04X", data[i]);
        printf("\n");

        for(i = 0; i < num_blocks; i++)                             //encrypt
            output[i] = data[i] ^ encrypt_word(CTR[i], key);

        printf("Ciphertext:\t0x");                                  //display output data
        for(i = 0; i < num_blocks; i++)
            printf("%04X", output[i]);
        printf("\n");

    } else if (decrypt_flag) {

        printf("Ciphertext:\t0x");                                   //display input data
        for(i = 0; i < num_blocks; i++)
            printf("%04X", data[i]);
        printf("\n");

        for(i = 0; i < num_blocks; i++)                             //decrypt
            output[i] = data[i] ^ encrypt_word(CTR[i], key);

        printf("Plaintext:\t0x");                                   //display output data
        for(i = 0; i < (num_blocks-1); i++)
            printf("%04X", output[i]);
        printf("%04X", output[num_blocks-1] & (0xffff << mis_bits));
        printf("\n");

    }

    //set up variables to print results to file, then do so if no errors are encountered
    char * outfile = argv[4];
    FILE * ofp = fopen(outfile, "w");
    int pad_length = mis_bits;
    if(ofp == NULL) {
    	printf("Cannot open output file. Exiting...\n");
        exit(1);
    } else {
    	for(i = 0; i < (num_blocks-1); i++) {
            word block  = output[i];
            byte left   = (block & 0xff00) >> 8;
            byte right  = (block & 0xff);
    		fprintf(ofp, "%s%s", byte_to_bit_string(left) , byte_to_bit_string(right) );
        }
        if(pad_length > 0) {                              //truncate last block if there was padding of the plaintext
            word block  = output[num_blocks-1];
            byte left   = (block & 0xff00) >> 8;
            byte right  = (block & 0xff);
            char * left_string = byte_to_bit_string(left);
            char * right_string = byte_to_bit_string(right);
            if(pad_length > 8){
                left_string[16 - pad_length] = '\0';
                fprintf(ofp,"%s",left_string);
            } else {
                right_string[8 - pad_length] = '\0';
                fprintf(ofp,"%s%s", left_string, right_string);
            }
        } else {                                            //if no padding of the plaintext, then output normally
            word block  = output[num_blocks-1];
            byte left   = (block & 0xff00) >> 8;
            byte right  = (block & 0xff);
            fprintf(ofp, "%s%s", byte_to_bit_string(left) , byte_to_bit_string(right) );
        }
    }
    fprintf(ofp,"\n");
    fclose(ofp);
}

//block encryption algorithm
word encrypt_word(word input, byte* key) {

	//take input and generate keys
	word output = input;

	byte * keys = generate_keys(key);
	word k1 = (keys[0] << 8) + keys[1];
	word k2 = (keys[2] << 8) + keys[3];
	word k3 = (keys[4] << 8) + keys[5];

    //round 1
	output = add_key(output,k1);

	//round 2
	output = n_substitution(output);
	output = shift_row(output);
	output = mix_column(output);
	output = add_key(output,k2);

	//round 3
	output = n_substitution(output);
	output = shift_row(output);
	output = add_key(output, k3);

	return output;
}

//block decryption algorithm
word decrypt_word(word input, byte* key) {

	//take input and generate keys in reverse order
    word output = input;

    byte * keys = generate_keys(key);
	word k3 = (keys[0] << 8) + keys[1];
	word k2 = (keys[2] << 8) + keys[3];
	word k1 = (keys[4] << 8) + keys[5];

    //round 1
	output = add_key(output,k1);

	//round 2
	output = shift_row(output);
	output = inv_n_substitution(output);
	output = add_key(output,k2);
	output = inv_mix_column(output);

	//round 3
	output = shift_row(output);
	output = inv_n_substitution(output);
	output = add_key(output, k3);

	return output;
}

//add key function
word add_key(word input, word key) {
    word output = input^key;
    return output;
}

//nibble substitution function
word n_substitution(word input) {
    byte b1 = (input & 0xff00) >> 8;
    byte b2 = input & 0xff;

    byte b1_sub = s_box_8(b1);
    byte b2_sub = s_box_8(b2);

    word output = (b1_sub << 8) + b2_sub;
    return output;
}

//inverse nibble substitution function
word inv_n_substitution(word input) {
    byte b1 = (input & 0xff00) >> 8;
    byte b2 = input & 0xff;

    byte b1_sub = inv_s_box_8(b1);
    byte b2_sub = inv_s_box_8(b2);

    word output = (b1_sub << 8) + b2_sub;
    return output;
}

//shift second row function
word shift_row(word input) {
    byte row_parts[4];

    int i;
    for(i = 0; i < 4; i++)
        row_parts[i] = ((0xf << 4*i) & input) >> (4*i);

    //swap second row nibbles
    byte temp = row_parts[0];
    row_parts[0] = row_parts[2];
    row_parts[2] = temp;

    word output = 0x0;
    for(i = 0; i < 4; i++)
        output += row_parts[i] << (4*i);

    return output;
}

//mix columns (matrix multiplication) function
word mix_column(word input) {
    byte in[4];
    byte out[4];

    int i;
    for(i = 3; i >= 0; i--)
        in[3-i] = ((0xf << 4*i) & input) >> (4*i);

    //perform matrix multiplication mod m(x)
    out[0] = in[0]^gf_mult_4(4,in[1]);
    out[1] = gf_mult_4(4,in[0])^in[1];
    out[2] = in[2]^gf_mult_4(4,in[3]);
    out[3] = gf_mult_4(4,in[2])^in[3];

    word output = 0x0;
    for(i = 3; i >= 0; i--)
        output += out[3-i] << (4*i);

    return output;
}

//inver mix columns (matrix multiplication) function
word inv_mix_column(word input) {
    byte in[4];
    byte out[4];

    int i;
    for(i = 3; i >= 0; i--)
        in[3-i] = ((0xf << 4*i) & input) >> (4*i);

    //perform matrix multiplication mod m(x)
    out[0] = gf_mult_4(9,in[0])^gf_mult_4(2,in[1]);
    out[1] = gf_mult_4(2,in[0])^gf_mult_4(9,in[1]);
    out[2] = gf_mult_4(9,in[2])^gf_mult_4(2,in[3]);
    out[3] = gf_mult_4(2,in[2])^gf_mult_4(9,in[3]);

    word output = 0x0;
    for(i = 3; i >= 0; i--)
        output += out[3-i] << (4*i);

    return output;
}

//returns the polynomial degree of the input byte
int poly_degree(byte poly) {
    int degree = 0;

    while(poly != 0){
        poly = poly >> 1;
        degree++;
    }

    return (degree-1);
}

//performs reduction mod m(x) for use after multiplication
byte gf_reduce_4(byte poly) {

    byte mx = 0x13;
    byte remainder = -1;
    int done = 0;

    int deg_div = 4;

    //polynomial division of input by m(x)
    byte cur_remain = poly;
    while ( 1 ) {
        int deg_rem = poly_degree(cur_remain);
        if(deg_div > deg_rem) {
            remainder = cur_remain;
            break;
        } else {
            int diff = deg_rem - deg_div;
            cur_remain = cur_remain^(mx << diff);
        }
    }

    return remainder;
}

//performs multiplication of two nibbles mod m(x)
byte gf_mult_4(byte poly1, byte poly2) {
    int i;
    byte result = 0x0;

    //multiply
    for(i = 0; i < 4; i++){
        if ( (0x1 & (poly1 >> i)) == 0x1 )
            result = (result^(poly2 << i));
    }

    //reduce mod m(x)
    byte remainder = gf_reduce_4(result);

    return remainder;
}

//print out binary representaiton of a byte (for diagnostic purposes, not used in main code)
void print_byte(byte out) {

    printf("0x%x:\t", out);

    //prints binary representation of hex byte
    int i;
    for(i = 7; i >=0; i--) {
        int bit_flag = ( (1 << i) & out ) >> i;
        printf("%d", bit_flag);
    }

    printf("\n");
}

//converts an ASCII character representing a hex digit to its byte form
byte convert_char_to_hex(char raw_input) {

    //get corresponding hex value from ASCII character
    char input = tolower(raw_input);
    byte output;
    if(input >= '0' && input <= '9')
        output = input - '0';
    else if(input >= 'a' && input <= 'f')
        output = input - 'a' + 10;
    else
        return (byte) input;

    return output;
}

//rotates a byte by 4 bits left, equivalent to shift right by 4 bits and swap nibbles
byte rotate_byte(byte input) {
    byte right = input & (0xf);
    byte left = input & (0xf0);

    byte output = (right << 4) + (left >> 4);

    return output;
}

//performs s-box substitution of a nibble
byte s_box_4(byte input) {

	byte sbox[4][4] = 	{{9,4,10,11},
                    	{13,1,8,5},
                    	{6,2,0,3},
                    	{12,14,15,7}};
   
    //get row and column sub-bits
    byte left = (input & 0xc) >> 2;
    byte right = input & 0x3;

    byte output = sbox[left][right];

    return output;
}

//performs inverse s-box substitution of a nibble
byte inv_s_box_4(byte input) {

    byte sbox[4][4] = 	{{10,5,9,11},
                    	{1,7,8,15},
                    	{6,0,2,3},
                    	{12,4,13,14}};

    byte left = (input & 0xc) >> 2;
    byte right = input & 0x3;

    byte output = sbox[left][right];

    return output;
}

//performs s-box substitution of each nibble in a byte (for convenience purposes)
byte s_box_8(byte input) {

    byte left = (input & 0xf0) >> 4;
    byte right = input & 0xf;

    byte left_sub = s_box_4(left);
    byte right_sub = s_box_4(right);

    byte output = (left_sub << 4) + right_sub;

    return output;
}

//performs inverse s-box substitution of each nibble in a byte (for convenience purposes)
byte inv_s_box_8(byte input) {

    byte left = (input & 0xf0) >> 4;
    byte right = input & 0xf;

    byte left_sub = inv_s_box_4(left);
    byte right_sub = inv_s_box_4(right);

    byte output = (left_sub << 4) + right_sub;

    return output;
}

//generates additional round keys from first key (key expansion)
byte * generate_keys(byte* in_key) {

    byte * keys = (byte*)malloc(6*sizeof(byte));

    //Rcon(x) for x in {1,2} values entered instead of calculated for convenience
    byte Rcon1 = 0x80;
    byte Rcon2 = 0x30;

    //from seed key
    keys[0] = (in_key[0] << 4) + in_key[1];
    keys[1] = (in_key[2] << 4) + in_key[3];

    //extended bytes for additional keys
    keys[2] = keys[0]^Rcon1^s_box_8(rotate_byte(keys[1]));
    keys[3] = keys[2]^keys[1];
    keys[4] = keys[2]^Rcon2^s_box_8(rotate_byte(keys[3]));
    keys[5] = keys[4]^keys[3];

    return keys;
}

//converts a bit string (ex "110110") of size up to 8 bits to type byte
byte bit_string_to_byte(char* bitstring) {
    int length = strlen(bitstring);
    byte val = 0x00;

    if(length > 8)
        return -1;
    else {
        int i;
        for(i = 0; i < length ; i++) {
            char cur_char = bitstring[i];

            //detect a '1' vs a '0', add and shift as necessary
            if(i != length)
                val = val << 1;
            if(cur_char == '1')
                val = val + 0x1;
        }
    }

    byte output = val;
    return val;
}

//converts a byte to its string representation in base 2
char* byte_to_bit_string(byte input) {
    char* bitstring = (char*)malloc(9*sizeof(char));

    int i;
    for(i = 0; i < 8; i++) {

        //detect bit value and print representative character
        int bit_flag = ((input << i) & 0x80) >> 7;
        if(bit_flag)                                    
            bitstring[i] = '1';
        else
            bitstring[i] = '0';
    }
    bitstring[8] = '\0';

    return bitstring;
}

//generate a word to use as an IV from a 16-bit int - should be relatively random
word generate_IV_from_nonce(int nonce, byte* key) {
    word data = nonce;
    int i;
    for(i = 0; i < 16; i++) {
        if(i%2 == 0)
            data = encrypt_word(data, key) << 1;
        else
            data = encrypt_word(data, key) >> 1;
    }
     return data;
}






