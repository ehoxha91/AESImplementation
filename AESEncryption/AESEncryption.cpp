#include "pch.h"
#include <iostream>




int main()
{
	return 0;
}

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
