/* Stages within Rounds

	1. Key Expansion
	2. Initial Round:
		AddRoundKey <-Message whittened
	3. Rounds:
		SubBytes
		ShiftRows
		MixColumns
		AddRoundKey -> Go to SubBytes (we repeat depending on key size)
	4. Final Round:
		SubBytes
		ShiftRows
		AddRoundKey
*/


#include <stdint.h>
#include "pch.h"
#include <iostream>
#include "LookupTables.h"
#include <conio.h>

using namespace std;

/* S-Box from wikipedia */
static unsigned char sbox[256] = {

	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F

	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,

	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,

	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,

	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,

	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,

	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,

	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,

	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,

	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,

	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,

	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,

	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,

	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,

	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,

	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,

	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

void AES_Encrypt(unsigned char* message, unsigned char* key);
void KeyExpansion(unsigned char* inputKey, unsigned char* expandedKeys);
void KeyExpansionCore(unsigned char* in, unsigned char i);
void SubBytes(unsigned char* state);
void ShiftRows(unsigned char* state);
void MixColumns(unsigned char*);
void AddRoundKey(unsigned char*, unsigned char*);

void PrintHex(unsigned char x)
{
	if (x / 16 < 10)  cout << (char)((x / 16) + '0');
	if (x / 16 >= 10)  cout << (char)((x / 16-10) + 'A');
	if (x % 16 < 10)  cout << (char)((x % 16) + '0');
	if (x % 16 >= 10)  cout << (char)((x % 16-10) + 'A');
}

int main()
{
	unsigned char message[] = "This is a message we will encrypt with AES!";
	unsigned char key[16] = { 1,2,3,4,
					 5,6,7,8,
					 9,10,11,12,
					 13,14,15,16 };

	int originalLen = strlen((const char*)message);
	int lenOfPaddedMessage = originalLen;

	if (lenOfPaddedMessage % 16 != 0)
		lenOfPaddedMessage = (lenOfPaddedMessage / 16 + 1) * 16;

	unsigned char* paddedMessage = new unsigned char[lenOfPaddedMessage];
	for (int i = 0; i < lenOfPaddedMessage; i++)
	{
		if (i >= originalLen) paddedMessage[i] = 0;
		else paddedMessage[i] = message[i];
	}

	for (int i = 0; i < lenOfPaddedMessage; i+=16)
	{
		AES_Encrypt(paddedMessage+i, key);
	}
	
	for (int i = 0; i < lenOfPaddedMessage; i++)
	{
		PrintHex(paddedMessage[i]);
		cout << " ";
	}
	delete[] paddedMessage;
	_getch();
	return 0;
}


void AES_Encrypt(unsigned char* message, unsigned char* key)
{
	unsigned char state[16]; // Take first 16 bytes
	for (int i = 0; i < 16; i++)
	{
		state[i] = message[i];
	}



	int numberOfRounds = 9;
	unsigned char expandedKey[176];
	//1. KeyExpansion
	KeyExpansion(key, expandedKey);

	//2. Initial Round
	AddRoundKey(state, key); // WhitteningStep/AddRoundKey

	//3. Rounds:
	for (int i = 0; i < numberOfRounds; i++)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, expandedKey+(16*(i+1)));
	}
	
	//4. Final Round
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, expandedKey+160);
	for (int i = 0; i < 16; i++)
	{
		message[i] = state[i];
	}
	
}


/* We need to generate 10 keyes, since we're implementing
AES 128, we will have 10 rounds(+initial round) and for 
each round we will need to generate a new key. That's what
this function does. */
void KeyExpansion(unsigned char* inputKey, unsigned char* expandedKeys)
{
	//First 16 bytes are the original key
	for (int i = 0; i < 16; i++)
	{
		expandedKeys[i] = inputKey[i];
	}

	
	unsigned int bytesGenerated = 16;	//We generated 16 bytes so far
	int rconIteration = 1;		//Rcon begins at 1
	unsigned char temp[4];		//Temporary storage for core.
	while (bytesGenerated<176)
	{
		for (int i = 0; i < 4; i++)
		{
			temp[i] = expandedKeys[i + bytesGenerated - 4];
		}

		//Let's call KeyExpansionCore after each key generated
		if (bytesGenerated%16 ==0)
		{
			KeyExpansionCore(temp, rconIteration++);
			rconIteration++;
		}
		//XOR temp with [bytesGenerated-16], and store in expandedKeys:
		for (unsigned char a = 0;a < 4; a++)
		{
			expandedKeys[bytesGenerated] =
				expandedKeys[bytesGenerated - 16] ^ temp[a];
			bytesGenerated++;
		}
	}
}

void KeyExpansionCore(unsigned char* in, unsigned char i)
{
	//Rotate left:
	unsigned char t = in[0];
	in[0] = in[1];
	in[1] = in[2];
	in[2] = in[3];
	in[3] = t;

	//Swap values with corresponding SBOX values.
	in[0] = sbox[in[0]];
	in[1] = sbox[in[1]];
	in[2] = sbox[in[2]];
	in[3] = sbox[in[3]];

	//Rcon
	in[0] ^= rcon[i];
}

/* In SubBytes step we repleace each byte of the state
with another byte depending on the key. The substitutions
are usuall presented as a Look-up table called Rijndael S-Box.
The S-Box consist of 256 byte substitutions arranged in a
16 x 16 grid. */
void SubBytes(unsigned char* state)
{
	for (int i = 0; i < 16; i++)
	{
		//Replace each byte of the state with the byte 
		//corresponding with the inxdex state[i] on sbox
		state[i] = sbox[state[i]];
	}
}

/* The ShiftRows step shifts the rows of the state to the left.
The first row is not shifted. The second row is shifted by 1 byte
to the left. The third row is shifted by two bytes, and the final
row is shifted by 3 bytes. When they are shifted left, they 
re-appear on the right(rotation) */
void ShiftRows(unsigned char* state)
{
	unsigned char tmp[16];

	tmp[0] = state[0];
	tmp[1] = state[5];
	tmp[2] = state[10];
	tmp[3] = state[15];

	tmp[4] = state[4];
	tmp[5] = state[9];
	tmp[6] = state[14];
	tmp[7] = state[3];

	tmp[8] = state[8];
	tmp[9] = state[13];
	tmp[10] = state[2];
	tmp[11] = state[7];

	tmp[12] = state[12];
	tmp[13] = state[1];
	tmp[14] = state[6];
	tmp[15] = state[11];
	
	for (int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}
}

void MixColumns(unsigned char* state)
{
	unsigned char tmp[16];

	//Galois field multiplication... Everything pre-calculated

	tmp[0] = (unsigned char)(mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
	tmp[1] = (unsigned char)(state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
	tmp[2] = (unsigned char)(state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
	tmp[3] = (unsigned char)(mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);

	tmp[4] = (unsigned char)(mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
	tmp[5] = (unsigned char)(state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
	tmp[6] = (unsigned char)(state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
	tmp[7] = (unsigned char)(mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);

	tmp[8] = (unsigned char)(mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
	tmp[9] = (unsigned char)(state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
	tmp[10] = (unsigned char)(state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
	tmp[11] = (unsigned char)(mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);

	tmp[12] = (unsigned char)(mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
	tmp[13] = (unsigned char)(state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
	tmp[14] = (unsigned char)(state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
	tmp[15] = (unsigned char)(mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);
	
	for (int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}

}

/* Galois fields, corresponds to XOR in the binary world. 
It's whitening step. State and the roundKey are added as Galois fields.
*/
void AddRoundKey(unsigned char* state, unsigned char* roundKey)
{
	for (int i = 0; i < 16; i++)
	{
		state[i] ^= roundKey[i];
	}
}



