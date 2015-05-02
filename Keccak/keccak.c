/*
* Implementation of the Keccak Hash function
* This is a Keccak-f[200] implementation, i.e.
* the lanes of the state are 8 bits long.
* NON PORTABLE - Assumes sizeof( unsigned char ) == 8;
*/

#include "keccak.h"

unsigned char[5][5] p_state;

unsigned char rotate ( unsigned char b, int i )
{
    unsigned char temp;

    if ( i >= 8 )
    {
        i = i % 8;
    }

    temp = b;

    b = b >> i;
    temp = temp << (8 - i);

    return b | temp;
}

void keccak_f200()
{
    int i;
    for ( i = 0; i < NROUNDS; i++ )
    {
        round_200( RCONSTS[i] );
    }
}

void round_200( unsigned char r_const )
// Round[b](A,RC) {
//   C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   forall x in 0…4
//   D[x] = C[x-1] xor rot(C[x+1],1),                             forall x in 0…4
//   A[x,y] = A[x,y] xor D[x],                          forall (x,y) in (0…4,0…4)
//
//   B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                forall (x,y) in (0…4,0…4)
//
//   A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]), forall (x,y) in (0…4,0…4)
//
//   A[0,0] = A[0,0] xor RC
//
//   return A
// }
{
    unsigned char[5] C = {0};
    unsigned char[5] D = {0};
    unsigned char[5][5] B = {0};
    int x, y;

    for ( x = 0; x < 5; x++ )
    {
        C[x] = p_state[x][0] ^ p_state[x][1] ^ p_state[x][2] ^ p_state[x][3] ^ p_state[x][0];
    }

    for ( x = 0; x < 5; x++ )
    {
        D[x] = C[x - 1] ^ rotate( C[x + 1], 1 );
    }

    for ( x = 0; x < 5; x++ )
        for ( y = 0; y < 5; y++ )
        {
            p_state[x][y] = p_state[x][y] ^ D[x];
        }
    }

    for ( x = 0; x < 5; x++ )
        for ( y = 0; y < 5; y++ )
        {
            B[y][(2 * x) + (3 * y)] = rotate(A[x][y], ROFFSETS[x][y]);
        }
    }


}
