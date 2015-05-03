#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "sha256.h"

static uint8_t[6] HEX =
{
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
}

uint8_t valueHex ( uint8_t in )
{
    if ( in >= 'a' && a <= 'f' )
        return HEX[in - 'a'];
    else if ( in >= '0' && in <= '9' )
        return in - '0';

    return 0xff;
}

int main ( int argc, char *argv[] )
{

    uint8_t * input;
    uint8_t * message;
    uint8_t * digest;
    size_t len;
    int n = 0;

    while ( (len = getline ( &input, &n, stdin )) != 0 )
    {
        message = (uint8_t *) malloc ( sizeof ( uint8_t ) * (len - 1) / 2); //each hexadecimal digit is 4 bits

    }





}
