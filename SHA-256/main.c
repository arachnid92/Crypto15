#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include "sha256.h"

static uint8_t HEX[6] =
{
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static uint8_t ASCII[6] =
{
    'a', 'b', 'c', 'd', 'e', 'f'
};

uint8_t joinHex ( uint8_t high, uint8_t low )
{

    uint8_t h_hex;
    uint8_t l_hex;

    if ( high >= 'a' && high <= 'f' )
        h_hex = HEX[high - 'a'];
    else if ( high >= '0' && high <= '9' )
        h_hex = high - '0';
    else
    {
        fprintf ( stderr, "joinHex: Value out of range.\n" );
        fprintf ( stderr, "H: %c, L: %c\n", high, low );
        exit (0xff);
    }

    if ( low >= 'a' && low <= 'f' )
        l_hex = HEX[low - 'a'];
    else if ( low >= '0' && low <= '9' )
        l_hex = low - '0';
    else
    {
        fprintf ( stderr, "joinHex: Value out of range.\n" );
        fprintf ( stderr, "H: %c, L: %c\n", high, low );
        exit (0xff);
    }

    return (h_hex << 4) | l_hex;
}

void splitHex ( uint8_t in, uint8_t * high, uint8_t * low )
{
    if ( (in >> 4) < 10 )
        *high = (in >> 4) + '0';
    else
        *high = ASCII[(in >> 4) - 10];

    if ( ((in << 4) >> 4) < 10 )
        *low = ((in << 4) >> 4) + '0';
    else
        *low = ASCII[((in << 4) >> 4) - 10];
}

int main ( int argc, char *argv[] )
{
    /* uint8_t * message; */
    uint8_t * digest;
    uint8_t input[128];
    uint8_t * chunk;
    size_t len = 0;
    uint8_t i = 0;
    uint8_t in;
    uint8_t eof = 0;
    uint8_t eol = 0;
    uint8_t h, l;

    initSHA256();

    while ( !eof )
    /* read each line, in chunks of 512bits at the time, and feed them to rsa256*/
    {
        chunk = ( uint8_t * ) malloc ( sizeof ( uint8_t ) * 64 );

        for ( len = 0; len < 128; len++  )
        {
            if ( scanf( "%1c", &in ) == EOF )
            {
                eof = 1;
                len--;
                break;
            }
            else if ( in == '\n' )
            {
                eol = 1;
                len--;
                break;
            }

            input[len] = in;
        }

        if ( eof )
        {
            free(chunk);
            break;
        }

        for ( i = 0; i < len + 1; i += 2 )
            chunk[i/2] = joinHex ( input[i], input[i + 1]);

        feedChunkSHA256 ( &chunk, (len + 1)/2 );

        if ( eol )
        {
            digest = ( uint8_t * ) malloc ( sizeof ( uint8_t ) * 32 );
            digestSHA256 ( &digest );
            for ( i = 0; i < 32; i++ )
            {
                splitHex ( digest[i], &h, &l );
                fprintf (stdout, "%c%c", h, l);
            }
            fprintf ( stdout, "\n");
            free(digest);
            initSHA256();
            eol = 0;
        }

        free(chunk);
    }

    return 0;
}
