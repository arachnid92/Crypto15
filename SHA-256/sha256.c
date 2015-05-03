/*
* Implementation of the SHA-256 hashing function
*/

#include "sha256.h"

uint32_t[64] MSA;
uint32_t[8] c_hash;

uint32_t rRotate ( uint32_t i, int x )
{
    return ( i >> x ) | ( i << (32 - x) )
}

size_t padInput ( uint8_t ** input, uint64_t len, uint8_t ** output )
// Receives the array which contains the input and pads it:
// 1. Append 0b10000000
// 2. Pad with k {0b0}'s such that 56 = len + k + 1 (mod) 64
// 3. Append len 8 bytes -> 56 + 8 (mod) 64 = 0
{
    size_t sout;
    int temp;
    int k;
    int i;

    temp = (len + 1) % 64;

    if ( temp > 56 )
        k = (64 - temp) + 56;
    else
        k = 56 - temp;

    sout = len + 1 + k + 8;

    if ( sout % 64 != 0 )
    {
        fprintf ( stderr, "ERROR PADDING: SOUT %d\nK %d\n", sout, k );
        exit(0x42);
    }

    *output = (uint8_t *) malloc ( sizeof ( uint8_t ) * sout );

    for ( i = 0; i < len; i++ ) //copy input to the first len bytes of output
        *output[i] = *input[i];

    *output[len] = PADHDER; //add the 0b10000000 padding byte

    for ( i = len + 1; i < len + k + 1; i++ ) //add the k 0b0 bytes
        *output[i] = PADTAIL;

    for ( i = 8; i > 0; i-- ) //append the length of the original array
        *output[sout - i] = (len << ( 64 - (8 * i) )) >> 56;

    return sout;
}

void RSA256 ( uint8_t ** input, uint64_t len, uint8_t ** digest )
{

    size_t padlen;
    uint8_t * padded;
    uint8_t[64] chunk;
    int i, j;

    for ( i = 0; i < 8; i++ )
        c_hash[i] = HASHCONST[i];

    *digest = (uint8_t *) malloc ( 32 * sizeof( uint8_t ) ); //256bits (32 bytes) digest

    padlen = padInput ( input, len, &padded );

    i = 0;
    while ( i < padlen )
    {
        for ( j = 0; j < i + 64; j++ )
        {
            chunk[j] = padded[i + j];
        }

        copyIntoMSA ( &chunk );
        extendMSA();
        compressHash();

        i += 64;
    }

    copyIntoDigest( &digest );

    free ( padded );

}

void copyIntoMSA ( uint8_t ** chunk )
// len (chunk) = 64 bytes (512 bits)
// fit into 16 32-bit words
{
    int i;
    int j = 0;
    uint32_t b1;
    uint32_t b2;
    uint32_t b3;
    uint32_t b4;


    while ( i < 64 )
    {

        b1 = (uint32_t *chunk[i]) << 24;
        b2 = (uint32_t *chunk[i++]) << 16;
        b3 = (uint32_t *chunk[i++]) << 8;
        b4 = (uint32_t *chunk[i++]);

        MSA[j] = b1 ^ b2 ^ b3 ^ b4;
        j++;

    }

}

void extendMSA ()
{

    int i;
    uint32_t s0;
    uint32_t s1;

    for ( i = 16; i < 64; i++ )
    // s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
    // s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
    // w[i] := w[i-16] + s0 + w[i-7] + s1
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
    a = c_hash[0];
    b = c_hash[1];
    c = c_hash[2];
    d = c_hash[3];
    e = c_hash[4];
    f = c_hash[5];
    g = c_hash[6];
    h = c_hash[7];

    //main compression loop:
    for ( i = 0; i < 64; i++ )
    {
        s1 = rRotate ( e, 6 ) ^ rRotate ( e, 11 ) ^ rRotate ( e, 25);
        ch = (e & f) ^ ((!e) & g);
        temp1 = h + s1 + ch + RNDCONST[i] + MSA[i];
        s1 = rRotate ( a, 2 ) ^ rRotate ( a, 13 ) ^ rRotate ( a, 22);
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

void copyIntoDigest ( uint8_t ** digest )
{

    int i = 0;
    int j = 0;

    while ( i < 32 )
    {

        *digest[i] = (uint8_t)(c_hash[j] >> 24);
        *digest[i++] = (uint8_t)(c_hash[j] << 8) >> 24;
        *digest[i++] = (uint8_t)(c_hash[j] << 16) >> 24;
        *digest[i++] = (uint8_t)(c_hash[j] << 24) >> 24;
        j++;

    }

}
