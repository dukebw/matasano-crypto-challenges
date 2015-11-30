#include "crypt_helper.h"

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;
typedef struct timespec timespec;

#define PORT 8181
#define IP_ADDRESS "192.168.11.42"

char Command[] = "test?file=index.html&signature=46b4ec586117154dacd49d664e5d63fdc88efb51";

const u8 HMAC_SHA_1_KEY_0[] =
{
	0x82, 0xF3, 0xB6, 0x9A, 0x1B, 0xFF, 0x4D, 0xE1, 0x5C, 0x33, 
};

const u8 HMAC_SHA_1_EXPECTED_HASH_0[] =
{
	0x1B, 0xA0, 0xE6, 0x6C, 0xF7, 0x2E, 0xFC, 0x34, 0x92, 0x07,
};

const u8 HMAC_SHA_1_MSG_0[] =
{
	0xFC, 0xD6, 0xD9, 0x8B, 0xEF, 0x45, 0xED, 0x68, 0x50, 0x80, 0x6E, 0x96, 0xF2, 0x55, 0xFA, 0x0C, 0x81, 0x14,
	0xB7, 0x28, 0x73, 0xAB, 0xE8, 0xF4, 0x3C, 0x10, 0xBE, 0xA7, 0xC1, 0xDF, 0x70, 0x6F, 0x10, 0x45, 0x8E, 0x6D,
	0x4E, 0x1C, 0x92, 0x01, 0xF0, 0x57, 0xB8, 0x49, 0x2F, 0xA1, 0x0F, 0xE4, 0xB5, 0x41, 0xD0, 0xFC, 0x9D, 0x41,
	0xEF, 0x83, 0x9A, 0xCF, 0xF1, 0xBC, 0x76, 0xE3, 0xFD, 0xFE, 0xBF, 0x22, 0x35, 0xB5, 0xBD, 0x03, 0x47, 0xA9,
	0xA6, 0x30, 0x3E, 0x83, 0x15, 0x2F, 0x9F, 0x8D, 0xB9, 0x41, 0xB1, 0xB9, 0x4A, 0x8A, 0x1C, 0xE5, 0xC2, 0x73,
	0xB5, 0x5D, 0xC9, 0x4D, 0x99, 0xA1, 0x71, 0x37, 0x79, 0x69, 0x23, 0x41, 0x34, 0xE7, 0xDA, 0xD1, 0xAB, 0x4C,
	0x8E, 0x46, 0xD1, 0x8D, 0xF4, 0xDC, 0x01, 0x67, 0x64, 0xCF, 0x95, 0xA1, 0x1A, 0xC4, 0xB4, 0x91, 0xA2, 0x64,
	0x6B, 0xE1, 
};

internal MIN_UNIT_TEST_FUNC(TestHmacSha1)
{
	u8 HmacScratch[SHA_1_HASH_LENGTH_BYTES];
	HmacSha1(HmacScratch, (u8 *)HMAC_SHA_1_MSG_0, sizeof(HMAC_SHA_1_MSG_0),
			 (u8 *)HMAC_SHA_1_KEY_0, sizeof(HMAC_SHA_1_KEY_0));
	MinUnitAssert(VectorsEqual(HmacScratch, (u8 *)HMAC_SHA_1_EXPECTED_HASH_0, sizeof(HMAC_SHA_1_EXPECTED_HASH_0)),
				  "Expected HMAC mismatch in TestBreakHmacSha1TimingLeak!");
}

internal MIN_UNIT_TEST_FUNC(TestBreakHmacSha1TimingLeak)
{
	i32 Status;

	i32 SocketFileDescriptor = socket(AF_INET, SOCK_STREAM, 0);
	Stopif(SocketFileDescriptor < 0, "Error from socket() call in TestBreakHmacSha1TimingLeak");

	sockaddr_in ServerSocketAddr;
	ServerSocketAddr.sin_family = AF_INET;
	ServerSocketAddr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
	ServerSocketAddr.sin_port = htons(PORT);

	timespec TimeSpec;
	Status = clock_getres(CLOCK_REALTIME, &TimeSpec);
	Stopif(Status == -1, "Error in getting clock resolution in TestBreakHmacSha1TimingLeak!");

	Status = connect(SocketFileDescriptor, (sockaddr *)&ServerSocketAddr, sizeof(ServerSocketAddr));
	Stopif(Status < 0, "Error from connect() call in TestBreakHmacSha1TimingLeak");

	printf("CLOCK_REALTIME resolution: tv_sec: %d tv_nsec: %ld\n", (int)TimeSpec.tv_sec, TimeSpec.tv_nsec);

	u8 ReceiveBuffer[8196];
	i32 ReadBytes;
	u64 ElapsedTime;
	do
	{
		write(SocketFileDescriptor, Command, STR_LEN(Command));

		Status = clock_gettime(CLOCK_REALTIME, &TimeSpec);
		Stopif(Status == -1, "Error in getting clocktime in TestBreakHmacSha1TimingLeak!");

		ElapsedTime = TimeSpec.tv_nsec;

		ReadBytes = read(SocketFileDescriptor, ReceiveBuffer, sizeof(ReceiveBuffer));
		Stopif(ReadBytes == sizeof(ReceiveBuffer), "Received message too long in TestBreakHmacSha1TimingLeak!");

		Status = clock_gettime(CLOCK_REALTIME, &TimeSpec);
		Stopif(Status == -1, "Error in getting clocktime in TestBreakHmacSha1TimingLeak!");

		ElapsedTime = TimeSpec.tv_nsec - ElapsedTime;

		printf("ElapsedTime: %lu\n", ElapsedTime);

		sleep(1);
	} while (memcmp(ReceiveBuffer, HMAC_VALID_STRING, sizeof(HMAC_VALID_STRING)));

	ReceiveBuffer[ReadBytes] = '\n';

	write(1, ReceiveBuffer, ReadBytes + 1);
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestHmacSha1);
	MinUnitRunTest(TestBreakHmacSha1TimingLeak);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
