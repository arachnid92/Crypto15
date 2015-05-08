#include <stdint.h>
#include <string.h>
#include "sha256.h"

/* Implementation of SHA256 */
/* For the Crypto15 course @KTH */
/* By Manuel Osvaldo Olguin Munoz */

static uint32_t K[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}; /* round keys */

uint32_t hash[8]; /*hash value*/
uint32_t W[64]; /*message schedule array*/

uint64_t b_len; /* message length in bits */
uint8_t c_len; /* current length of the chunk */
uint8_t chunk8[64]; /* the current chunk being filled */
uint32_t chunk32[16]; /* the current chunk, filled and padded */

uint32_t rotateRight ( uint32_t x, uint32_t i )
{
    return ( x >> i ) | ( x << (32 - i) );
}

/* Next we define the functions of SHA256 as specified by FIPS PUB 180-4 */
uint32_t Ch ( uint32_t x, uint32_t y, uint32_t z )
{
    return ( x & y ) ^ ( ~x & z );
}

uint32_t Maj ( uint32_t x, uint32_t y, uint32_t z )
{
    return ( x & y ) ^ ( x & z ) ^ ( y & z );
}

uint32_t BigSigma0( uint32_t x )
{
    return rotateRight ( x, 2 ) ^ rotateRight ( x, 13 ) ^ rotateRight ( x, 22 );
}
uint32_t BigSigma1( uint32_t x )
{
    return rotateRight ( x, 6 ) ^ rotateRight ( x, 11 ) ^ rotateRight ( x, 25 );
}
uint32_t SmallSigma0( uint32_t x )
{
    return rotateRight ( x, 7 ) ^ rotateRight ( x, 18 ) ^ ( x >> 3 );
}
uint32_t SmallSigma1( uint32_t x )
{
    return rotateRight ( x, 17 ) ^ rotateRight ( x, 19 ) ^ ( x >> 10 );
}

void initSHA256 ()
/* initialize the hash values and reset all other variables to 0 */
{
    hash[0] = 0x6a09e667;
    hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372;
    hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f;
    hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab;
    hash[7] = 0x5be0cd19;

    b_len = 0;
    c_len = 0;
    memset(W, 0, sizeof(W));
    memset(chunk8, 0, sizeof(chunk8));
    memset(chunk32, 0, sizeof(chunk32));
}

void feedByteSHA256 ( uint8_t byte, uint8_t done )
/* input one byte into the state */
/* the done flag indicates if all bytes have already been inputted. */
/* if done == 1, the input byte is discarded */
{

    if ( done )
    {
        padChunk();
        return;
    }

    chunk8[c_len] = byte;
    c_len++;
    b_len += 8;

    if ( c_len == 64 )
        padChunk();

}

uint32_t bytes2Int ( uint8_t h, uint8_t m1, uint8_t m2, uint8_t l)
/* joins 4 bytes into a 32-bit integer */
{
    uint32_t a = h;
    uint32_t b = m1;
    uint32_t c = m2;
    uint32_t d = l;

    a = a << 24;
    b = b << 16;
    c = c << 8;

    return a | b | c | d;
}

uint8_t long2Byte ( uint64_t l, uint8_t pos )
/* returns the byte at position pos in the specified long */
{
    uint64_t r = l << (pos * 8);
    return r >> 56;
}

uint8_t int2Byte ( uint32_t i, uint8_t pos )
/* returns the byte at position pos in the specified int */
{
    uint32_t r = i << (pos * 8);
    return  r >> 24;
}

void padChunk()
/* pads the current chunk */
/* if not the last chunk, just converts it to 32byte format for easier manipulation */
/* after padding and convertion, runs the compression function on the chunk */
{
    int i;
    int r;
    if ( c_len == 64 )
    {
        for ( i = 0; i < 16; i++ )
        {
            chunk32[i] = bytes2Int ( chunk8[i*4], chunk8[i*4 + 1], chunk8[i*4 + 2], chunk8[i*4 + 3]);
        }

        memset(chunk8, 0, sizeof(chunk8)); /* free space for next chunk */
        c_len = 0;

        processChunk();
        return;
    }
    else if ( (r = 56 - c_len ) > 0 ) /* c_len < 56 */
    {
        chunk8[c_len] = 0x80; /* the 1 bit padding and its zeros */
        c_len++;

        for ( ; c_len < 56; c_len++ ) /* the k 0s padding */
            chunk8[c_len] = 0x00;

        for ( i = 0; i < 8; i++ ) /* copy total length to last 8 bytes */
            chunk8[c_len + i] = long2Byte(b_len, i);

        c_len += 8; /* should be 64 */

        for ( i = 0; i < 16; i++ )
            chunk32[i] = bytes2Int ( chunk8[i*4], chunk8[i*4 + 1], chunk8[i*4 + 2], chunk8[i*4 + 3]);

        memset(chunk8, 0, sizeof(chunk8)); /* dont need this memory anymore */
        c_len = 0;

        processChunk();
        return;

    }
    else /* c_len >= 56 < 64 */
         /* need to add a whole chunk (512 bits) of padding and then some */
    {

        chunk8[c_len] = 0x80; /* the 1 bit padding and its zeros */
        c_len++;

        for ( ; c_len < 64; c_len++ ) /* the k 0s padding */
            chunk8[c_len] = 0x00;

        for ( i = 0; i < 16; i++ )
            chunk32[i] = bytes2Int ( chunk8[i*4], chunk8[i*4 + 1], chunk8[i*4 + 2], chunk8[i*4 + 3]);

        memset(chunk8, 0, sizeof(chunk8)); /* dont need this memory anymore */
        c_len = 0;

        processChunk();

        for ( ; c_len < 56; c_len++ ) /* the k 0s padding */
            chunk8[c_len] = 0x00;

        for ( i = 0; i < 8; i++ ) /* copy total length to last 8 bytes */
            chunk8[c_len + i] = long2Byte(b_len, i);

        c_len += 8; /* should be 64 */

        for ( i = 0; i < 16; i++ )
            chunk32[i] = bytes2Int ( chunk8[i*4], chunk8[i*4 + 1], chunk8[i*4 + 2], chunk8[i*4 + 3]);

        memset(chunk8, 0, sizeof(chunk8)); /* dont need this memory anymore */
        c_len = 0;

        processChunk();
        return;
    }

}

void processChunk()
/* compression function */
{
    uint32_t a, b, c, d, e, f, g, h, temp1, temp2;
    int t;

    prepareMessageSchedule();
    memset(chunk32, 0, sizeof(chunk32)); /* free the chunk, dont need it anymore! */

    /* initialize working variables */
    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    /* compression loop */
    for ( t = 0; t < 64; t++ )
    {
        temp1 = h + BigSigma1(e) + Ch(e, f, g) + K[t] + W[t];
        temp2 = BigSigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;

    }

    /* store hash */
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;

}

void prepareMessageSchedule()
/* inputs the current chunk into the message schedule */
{

    int t;
    for ( t = 0; t < 16; t++ )
    {
        W[t] = chunk32[t];
    }

    for ( t = 16; t < 64; t++ )
    {
        W[t] = SmallSigma1(W[t - 2]) + W[t - 7] + SmallSigma0(W[t - 15]) + W[t - 16];
    }

}

uint8_t getByteFromHashSHA256( uint8_t pos )
/* returns a byte from the digest */
{
    uint8_t row = pos / 4;
    uint8_t col = pos % 4;

    return int2Byte( hash[row], col );
}
