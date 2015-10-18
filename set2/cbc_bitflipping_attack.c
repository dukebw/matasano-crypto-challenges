#include "crypt_helper.h"

const char PREPEND_STRING[] = "comment1=cooking%20MCs;userdata=";
#define PREPEND_LENGTH (sizeof(PREPEND_STRING) - 1)
const char APPEND_STRING[] = "comment1=cooking%20MCs;userdata=";
#define APPEND_LENGTH (sizeof(APPEND_STRING) - 1)
const char ADMIN_TRUE_STRING[] = ";admin=true;";
#define ADMIN_TRUE_STR_LENGTH (sizeof(ADMIN_TRUE_STRING) - 1)

CASSERT(ADMIN_TRUE_STR_LENGTH < (PREPEND_LENGTH - AES_128_BLOCK_LENGTH_BYTES), cbc_bitflipping_attack_c);

internal MIN_UNIT_TEST_FUNC(TestCiphertextModification)
{
	u8 ScratchInput[256];
	u8 RandValue[sizeof(ScratchInput) - PREPEND_LENGTH - APPEND_LENGTH];
	memcpy(ScratchInput, PREPEND_STRING, PREPEND_LENGTH);

	u32 RandomInputLengthBytes;
	RandomInputLengthBytes = rand() % sizeof(RandValue);
	GenRandBytesUnchecked(RandValue, RandomInputLengthBytes);

	u32 ScratchInputIndex = PREPEND_LENGTH;
	for (u32 RandValueIndex = 0;
		 RandValueIndex < RandomInputLengthBytes;
		 ++RandValueIndex)
	{
		u8 NextRandByte = RandValue[RandValueIndex];
		if ((NextRandByte != ';') && (NextRandByte != '='))
		{
			ScratchInput[ScratchInputIndex] = NextRandByte;
			++ScratchInputIndex;
		}
	}
	memcpy(ScratchInput + ScratchInputIndex, APPEND_STRING, APPEND_LENGTH);
	u32 TotalInputLength = (ScratchInputIndex + APPEND_LENGTH);
	Stopif(TotalInputLength > sizeof(ScratchInput), "Overflowed ScratchInput");

	u32 Iv[AES_128_BLOCK_LENGTH_WORDS];
	GenRandUnchecked(Iv, AES_128_BLOCK_LENGTH_WORDS);
	u32 Key[AES_128_BLOCK_LENGTH_WORDS];
	GenRandUnchecked(Key, AES_128_BLOCK_LENGTH_WORDS);

	AesCbcEncrypt(ScratchInput, ScratchInput, TotalInputLength, (u8 *)Key, sizeof(Key), (u8 *)Iv);

	u8 PlaintextXorAdminTrue[AES_128_BLOCK_LENGTH_BYTES];
	XorVectorsUnchecked(PlaintextXorAdminTrue,
						(u8 *)ADMIN_TRUE_STRING,
						(u8 *)PREPEND_STRING + AES_128_BLOCK_LENGTH_BYTES,
						ADMIN_TRUE_STR_LENGTH);
	XorVectorsUnchecked(ScratchInput, ScratchInput, PlaintextXorAdminTrue, ADMIN_TRUE_STR_LENGTH);

	AesCbcDecrypt(ScratchInput, ScratchInput, TotalInputLength, (u8 *)Key, sizeof(Key), (u8 *)Iv);

	b32 AdminTrueFound = false;
	for (u32 AdminTrueCheckIndex = 0;
		 AdminTrueCheckIndex <= (TotalInputLength - ADMIN_TRUE_STR_LENGTH);
		 ++AdminTrueCheckIndex)
	{
		if (memcmp(ScratchInput + AdminTrueCheckIndex, ADMIN_TRUE_STRING, ADMIN_TRUE_STR_LENGTH) == 0)
		{
			AdminTrueFound = true;
			break;
		}
	}
	MinUnitAssert(AdminTrueFound, "Ciphertext didn't contain ;admin=true;");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	srand(time(0));
	MinUnitRunTest(TestCiphertextModification);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
