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
#include <iomanip>

using namespace std;

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
	unsigned char message[] = "As input take this string!";
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
		//PrintHex(paddedMessage[i]);
		cout << hex << (int)paddedMessage[i];
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

	
	int bytesGenerated = 16;	//1st 16 are original key
	int rconIteration = 1;		//Rcon begins at 1
	unsigned char temp[4];		//Temporary storage for core.

	while (bytesGenerated<176)
	{
		//Last generated...
		for (int i = 0; i < 4; i++)
		{
			temp[i] = expandedKeys[i + bytesGenerated - 4];
		}

		//Let's call KeyExpansionCore after each key generated
		if (bytesGenerated % 16 ==0)
		{
			KeyExpansionCore(temp, rconIteration);
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



