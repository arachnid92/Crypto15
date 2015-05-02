#define NROUNDS 18

static unsigned char[NROUNDS] RCONSTS =
{
    0x01, 0x82, 0x8A, 0x00, 0x8b, 0x01,
    0x81, 0x09, 0x8A, 0x88, 0x09, 0x0A,
    0x8B, 0x8B, 0x89, 0x03, 0x02, 0x80
};

static unsigned int[5][5] ROFFSETS =
{
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14}

};

void keccak_f200();
void round_200( unsigned char r_const );
unsigned char rotate( unsigned char b, int i );
