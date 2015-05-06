/*
* Implementation of the SHA-256 hashing function
*/

#include "sha256.h"

static uint32_t HASHCONST[8] =
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static uint32_t RNDCONST[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t MSA[64];
uint32_t c_hash[8];
uint64_t in_len;

uint32_t rRotate ( uint32_t i, int x )
{
    fprintf ( stderr, "rotating\n");
    return ( i >> x ) | ( i << (32 - x) );
}

size_t padInput ( uint8_t ** input, uint64_t len, uint8_t ** output )
/* Receives the array which contains the input and pads it:
* 1. Append 0b10000000
* 2. Pad with k {0b0}'s such that 56 = len + k + 1 (mod) 64
* 3. Append len 8 bytes -> 56 + 8 (mod) 64 = 0 */
{
    size_t sout;
    int k;
    int i;

    fprintf ( stderr, "Padding\n");

    if ( len + 1 > 56 )
        k = (64 - (len + 1)) + 56;
    else
        k = 56 - (len + 1);

    sout = len + 1 + k + 8;

    fprintf ( stderr, "Padding length: %ld\n", sout);
    fprintf ( stderr, "0's: %d\n", k);
    fprintf ( stderr, "Init len: %ld\n", len);

    if ( sout % 64 != 0 )
    {
        fprintf ( stderr, "ERROR PADDING: SOUT %ld\nK %d\n", sout, k );
        exit(0x42);
    }

    fprintf ( stderr, "%ld \n", sout );
    *output = (uint8_t *) malloc ( sizeof ( uint8_t ) * sout );

    fprintf ( stderr, "Copying input to pad\n");
    for ( i = 0; i < len; i++ ) /* copy input to the first len bytes of output */
        *output[i] = *input[i];

    fprintf ( stderr, "Adding 0b10000000\n");
    *output[len] = PADHDER; /* add the 0b10000000 padding byte */

    fprintf ( stderr, "Adding %d 0's\n", k );
    for ( i = len + 1; i < len + k + 1; i++ ) /* add the k 0b0 bytes */
        *output[i] = PADTAIL;

    fprintf ( stderr, "Appending length %ld\n", in_len);
    for ( i = 8; i > 0; i-- ) /* append the total length of the message */
        *output[sout - i] = (in_len << ( 64 - (8 * i) )) >> 56;

    return sout;
}

void initSHA256()
{
    int i;

    fprintf ( stderr, "Init SHA\n");

    for ( i = 0; i < 8; i++ )
        c_hash[i] = HASHCONST[i];

    for ( i = 0; i < 64; i++ )
        MSA[i] = 0;

    in_len = 0;
}

void feedChunkSHA256 ( uint8_t ** chunk, size_t len )
{

    size_t padlen;
    uint8_t * padded;
    int i, j;

    fprintf ( stderr, "Feeding Chunk. Length: %ld\n", len );

    in_len += len;

    if ( len < 64 )
    {
        /* pad and process */

        padlen = padInput ( chunk, (uint64_t) len, &padded );

        for ( i =0; i < padlen; i += 64 )
        {
            for ( j = 0; j < i + 64; j++ )
            {
                *chunk[j] = padded[i + j];
            }

            copyIntoMSA ( chunk );
            extendMSA();
            compressHash();
        }

        free ( padded );
    }
    else
    {
        copyIntoMSA ( chunk );
        extendMSA();
        compressHash();
    }

}

void copyIntoMSA ( uint8_t ** chunk )
/* len (chunk) = 64 bytes (512 bits)
* fit into 16 32-bit words */
{

    int i;
    int j = 0;
    uint32_t b1;
    uint32_t b2;
    uint32_t b3;
    uint32_t b4;

    fprintf ( stderr, "Copying to MSA\n");

    while ( i < 64 )
    {

        b1 = ((uint32_t) *chunk[i]) << 24;
        b2 = ((uint32_t) *chunk[i++]) << 16;
        b3 = ((uint32_t) *chunk[i++]) << 8;
        b4 = ((uint32_t) *chunk[i++]);

        MSA[j] = b1 ^ b2 ^ b3 ^ b4;
        j++;

    }

}

void extendMSA ()
{

    int i;
    uint32_t s0;
    uint32_t s1;

    fprintf ( stderr, "Extending MSA\n");

    for ( i = 16; i < 64; i++ )
    {

        s0 = rRotate( MSA[i - 15], 7 ) ^ rRotate( MSA[i - 15], 18 ) ^ MSA[i - 15] >> 3;
        s1 = rRotate( MSA[i - 2], 17 ) ^ rRotate( MSA[i - 2], 19 ) ^ MSA[i - 2] >> 10;
        MSA[i] = MSA[i - 16] + s0 + MSA[i - 7] + s1;

    }

}

void compressHash ()
{

    int i;
    uint32_t s0, s1, ch, temp1, temp2, maj;
    uint32_t a, b, c, d, e, f, g, h;

    fprintf ( stderr, "Compressing hash\n");

    a = c_hash[0];
    b = c_hash[1];
    c = c_hash[2];
    d = c_hash[3];
    e = c_hash[4];
    f = c_hash[5];
    g = c_hash[6];
    h = c_hash[7];

    /* main compression loop: */
    for ( i = 0; i < 64; i++ )
    {
        s1 = rRotate ( e, 6 ) ^ rRotate ( e, 11 ) ^ rRotate ( e, 25);
        ch = (e & f) ^ ((!e) & g);
        temp1 = h + s1 + ch + RNDCONST[i] + MSA[i];
        s0 = rRotate ( a, 2 ) ^ rRotate ( a, 13 ) ^ rRotate ( a, 22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    c_hash[0] += a;
    c_hash[1] += b;
    c_hash[2] += c;
    c_hash[3] += d;
    c_hash[4] += e;
    c_hash[5] += f;
    c_hash[6] += g;
    c_hash[7] += h;
}

void digestSHA256 ( uint8_t ** digest )
/* outputs the digest */
{

    int i = 0;
    int j = 0;

    fprintf ( stderr, "Digesting\n");

    while ( i < 32 )
    {

        *digest[i] = (uint8_t)(c_hash[j] >> 24);
        *digest[i++] = (uint8_t)(c_hash[j] << 8) >> 24;
        *digest[i++] = (uint8_t)(c_hash[j] << 16) >> 24;
        *digest[i++] = (uint8_t)(c_hash[j] << 24) >> 24;
        j++;

    }

}
