/* Convention adopted: ARRAY[ROW][COLUMN] */
/* THIS IS A AES-128 (16 bytes) IMPLEMENTATION */

/* Author: Manuel Osvaldo Olguin Munoz */
/* molguin@dcc.uchile.cl || mojom@kth.se */
/* Universidad de Chile || KTH Royal Institute of Technology */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define KEY_SIZE 16
#define EXP_KEY_SIZE 176
#define ROUNDS 10
#define BLOCK_SIZE 16

void subBytes ( );
void shiftRows ( );
void mixColumns ( );
void addRoundKey ( unsigned char * exp_key, unsigned char r_count );
void cycleRowLeft ( unsigned char row, unsigned char n );
unsigned char gfMult ( unsigned char a, unsigned char x );
unsigned char gfMult2 ( unsigned char x );
unsigned char gfMult3 ( unsigned char x );
void keySchedCore ( unsigned char * word, unsigned char iter );
void expandKey ( unsigned char * key, unsigned char * exp_key );
void encryptBlockAES ( unsigned char * exp_key );
void encryptAES ( unsigned char * key,
                    unsigned char * m,
                    unsigned char * c,
                    size_t length );

static unsigned char sbox [256] = /* Precalculated RINJDAEL SBOX */
{
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static unsigned char rcon [256] = /* Precalculated RCon */
{
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
  0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
  0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
  0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
  0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
  0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
  0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
  0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
  0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
  0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
  0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
  0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
  0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
  0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
  0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

static unsigned char multMatrix[4][4] =
/* Matrix used in the MixColumns steps */
{
    {2, 3, 1, 1},
    {1, 2, 3, 1},
    {1, 1, 2, 3},
    {3, 1, 1, 2}
};

unsigned char state[4][4]; /* state of the cipher */

void cycleRowLeft ( unsigned char row, unsigned char n )
/* auxiliary function, cycles the specified row n slots to the left. */
{
    unsigned char temp;
    unsigned char i;

    while ( n != 0 )
    {
        temp = state[row][0];
        for ( i = 0; i < 3; i++ )
            state[row][i] = state[row][i + 1];
        state[row][3] = temp;

        n--;
    }
}

unsigned char gfMult ( unsigned char a, unsigned char x )
/* auxiliary wrapper function, multiplies x with a constant (a), which takes one
of three possible values: 1, 2 or 3. Multiplication is done in GF(2^8). */
{
    switch ( a )
    {
        case 1:
            return x;
            break;
        case 2:
            return gfMult2 ( x );
            break;
        case 3:
            return gfMult3 ( x );
            break;
        default:
            fprintf ( stderr, "gfMult: INVALID CONSTANT --- A = %d\n", a );
            exit(1);
            break;
    }
}

unsigned char gfMult2 ( unsigned char x )
/* auxiliary function, multiplies a byte with 2, following the GF(2^8) rules. */
{
    if ( x & 0x80 ) /* 0x80 = 1000 0000 -> if high of x bit is 1, this is true */
        return ( ( x << 1 ) ^ 0x1B );

    return ( x << 1 );
}

unsigned char gfMult3 ( unsigned char x )
/* auxiliary function, multiplies a byte with 3, following the GF(2^8) rules. */
{
    return gfMult2 ( x ) ^ x;
}

void addRoundKey ( unsigned char * exp_key, unsigned char r_count )
/* adds a roundkey to the state according to the current round count */
{
    unsigned char i;
    unsigned char j;

    for ( i = 0; i < 4; i++ )
        for ( j = 0; j < 4; j++ )
            state[j][i] = state[j][i] ^ exp_key[ KEY_SIZE * r_count + (( 4 * i ) + j ) ];
}

void shiftRows ()
{
    unsigned char row;

    for ( row = 1; row < 4; row++ )
        cycleRowLeft ( row, row );
}

void subBytes ()
/* Sbox lookup, basically */
{
    unsigned char i;
    unsigned char j;

    for ( i = 0; i < 4; i++ )
        for ( j = 0; j < 4; j++ )
            state[i][j] = sbox[state[i][j]];
}

void mixColumns ()
{
    unsigned char i;
    unsigned char j;
    unsigned char res[4][4]; /* holds the result of the multiplication */

    for ( i = 0; i < 4; i++ )
    { /* for each column */

        for ( j = 0; j < 4; j++ )
        {
            res[j][i] =
                    gfMult ( multMatrix[j][0], state[0][i] ) ^ \
                    gfMult ( multMatrix[j][1], state[1][i] ) ^ \
                    gfMult ( multMatrix[j][2], state[2][i] ) ^ \
                    gfMult ( multMatrix[j][3], state[3][i] );
        }
    }

    for ( i = 0; i < 4; i++ )
        for ( j = 0; j < 4; j++ )
            state[j][i] = res[j][i];

}

void keySchedCore ( unsigned char * word, unsigned char iter )
/* KEY SCHEDULE CORE ROUTINE */
{
    unsigned char temp;
    unsigned char i;

    /* ROTATE */
    temp = word[0];
    for ( i = 0; i < 3; i++ )
        word[i] = word[i + 1];
    word[3] = temp;

    /* SBOX */
    for ( i = 0; i < 4; i++ )
        word[i] = sbox[word[i]];

    /* RCON */
    word[0] = word[0] ^ rcon[iter];
}

void expandKey ( unsigned char * key, unsigned char * exp_key )
/* Expands the 16 byte key into 176 bytes of roundkeys */
{
    unsigned char size = KEY_SIZE;
    unsigned char rcon_count = 0;
    unsigned char word[4];
    unsigned char i;

    for ( i = 0; i < KEY_SIZE; i++ )
        exp_key[i] = key[i];

    while ( size < EXP_KEY_SIZE )
    /* while we haven't reached the desired key lenght, keep expanding! */
    {
        for ( i = size - 4; i < size; i++ )
            word[i + 4 - size] = exp_key[i];

        if ( !(size % KEY_SIZE) ) /* Every 16 bytes we run the core again. */
        {
            rcon_count++;
            keySchedCore ( word, rcon_count );
        }

        for ( i = 0; i < 4; i++ )
        {
            exp_key[size] = exp_key[size - KEY_SIZE] ^ word[i];
            size++;
        }
    }

}

void encryptBlockAES ( unsigned char * exp_key )
/* basically, encrypts whatever is on the state at the moment */
{
    unsigned char r_count = 0;

    addRoundKey ( exp_key, r_count );

    for ( r_count = 1; r_count < ROUNDS - 1; r_count++ )
    /* firs n-1 rounds */
    {
        subBytes();
        shiftRows();
        mixColumns();
        addRoundKey ( exp_key, r_count );
    }

    /* Last round, no MixColumns */
    subBytes();
    shiftRows();
    addRoundKey ( exp_key, r_count );
}

void encryptAES ( unsigned char * key,
                    unsigned char * m,
                    unsigned char * c,
                    size_t length )
{
    /* OBS: This function assumes the message to encrypt, m, is of appropiate
    lenght, i.e. lenght(m) % BLOCK_SIZE = 0!

    key is the cipher key
    m is the original plaintext, PADDED with 0 to fit the block lenght
    c is the final ciphertext
    length is the lenght of both arrays */

    unsigned char exp_key[EXP_KEY_SIZE];
    int n_blocks = length / BLOCK_SIZE; /* Nr of blocks to process */
    unsigned char i;
    unsigned char col;
    unsigned char row;

    expandKey ( key, exp_key );

    for ( i = 0; i < n_blocks; i++ )
    /* ENCRYPT EACH BLOCK SEPARATELY */
    {
        for ( col = 0; col < 4; col++ )
            for ( row = 0; row < 4; row++ )
                state[row][col] = m[(4 * col) + row + (i * BLOCK_SIZE)];

        encryptBlockAES ( exp_key );

        for ( col = 0; col < 4; col++ )
            for ( row = 0; row < 4; row++ )
                c[(4 * col) + row + (i * BLOCK_SIZE)] = state[row][col];
    }
}

int main ( int argc, char *argv[] )
{
    unsigned char key[KEY_SIZE];
    unsigned char plain[BLOCK_SIZE];
    unsigned char cipher[BLOCK_SIZE];
    size_t i;

    i = scanf ( "%16c", key );
    /* fprintf ( stdout, "KEY: %s\n", key); */

    while ( scanf ( "%16c", plain ) != EOF )
    {
        encryptAES ( key, plain, cipher, BLOCK_SIZE );
        fprintf ( stdout, "%s", cipher );
    }

    fflush ( stdout );
    return 0;

}
