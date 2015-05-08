#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "sha256.h"

static char HEX[16] =
{
    '0', '1', '2', '3',
    '4', '5', '6', '7',
    '8', '9', 'a', 'b',
    'c', 'd', 'e', 'f'
};

static char HHEX[6] =
{
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

void digest ()
{
    uint8_t i;
    uint8_t out;
    uint8_t high;
    uint8_t low;

    feedByteSHA256 ( 0, 1 );
    for ( i = 0; i < 32; i++ )
    {
        out = getByteFromHashSHA256 ( i );
        high = out >> 4;
        low = (out << 4);
        low = low >> 4;
        fprintf ( stdout, "%c", HEX[ high ] );
        fprintf ( stdout, "%c", HEX[ low ] );
    }
    fprintf ( stdout, "\n" );
    initSHA256();
}

uint8_t parseHex ( uint8_t c )
{
    if ( c >= 'a' && c <= 'f' )
        return HHEX[c - 'a'];
    else if ( c >= '0' && c <= '9' )
        return c - '0';
    else
        return 0xff;
}

uint8_t hexChars2Byte ( uint8_t h, uint8_t l )
{
    h = parseHex ( h );
    l = parseHex ( l );

    return (h << 4) | l;

}

int main ( int argc, char *argv[] )
{

    char hexh;
    char hexl;

    initSHA256();

    while ( ( hexh = getchar() ) != EOF )
    {
        if ( hexh == '\n' )
        {
            digest();
            continue;
        }

        hexl = getchar();

        feedByteSHA256 ( hexChars2Byte ( hexh, hexl ), 0 );
    }

    return 0;
}
