#ifndef HELPER_H
#define HELPER_H

#include "stopif.h"
#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define internal static
#define local_persist static
#define global_variable static

#define ArrayLength(array) sizeof(array)/sizeof((array)[0])

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef int32 bool32;

typedef float real32;
typedef double real64;

// NOTE(brendan): swap the characters s and t (xor trick)
void Swap(char *s, char *t);

// NOTE(brendan): INPUT: hex character. OUTPUT: integer value of hex character
int Base16ToInteger(char Value);

// NOTE(brendan): reverses string s and returns pointer to start of s;
// side-effects
char *ReverseString(char *s);

// NOTE(brendan): INPUT: output char array, two input ASCII char arrays, all of
// same length. OUTPUT: output char array gets the result of XORing the
// two input char arrays
inline void
XORAsciiStrings(char *Result, char *StringA, char *StringB, uint32 Length);

// NOTE(brendan): INPUT: output char array, two input hex char arrays, all of
// same length, which is passed as Length. OUTPUT: output char array gets the
// result of XORing the two input char arrays
void XORStrings(char *Result, char *StringA, char *StringB, uint32 Length);

// NOTE(brendan): INPUT: output string, hex-encoded string. OUTPUT: string
// of characters
void DecodeHexString(char *Result, char *HexString, uint32 Length);

// NOTE(brendan): INPUT: Ciphertext, length of ciphertext.
// OUTPUT: string with max score based on frequency analysis, and from trying
// all byte ciphers
real32 ByteCipherInHexDecode(char *DecodedString, char *Ciphertext,
                             uint32 CipherLength);

// NOTE(brendan): INPUT: Ciphertext in ASCII-256, length of ciphertext.
// OUTPUT: string with max score based on frequency analysis, and from trying
// all byte ciphers
// Returns the MinCipher
uint8 ByteCipherAsciiDecode(char *DecodedString, char *Ciphertext,
                            uint32 CipherLength);

// NOTE(brendan): read a line into s; return length
int GetLine(char OutString[], int Limit);

// NOTE(brendan): OUTPUT: OutHex[] array of hex values corresponding to input
// string.  INPUT: String[], Length of String
void StringToHex(char OutHex[], char String[], uint32 Length);

#endif /* HELPER_H */
