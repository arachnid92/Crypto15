#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#define PADHDER 0x80
#define PADTAIL 0x00

size_t padInput ( uint8_t ** input, uint64_t len, uint8_t ** output );
uint32_t rRotate ( uint32_t i, int x );
void feedChunkSHA256 ( uint8_t ** chunk, size_t len );
void copyIntoMSA ( uint8_t ** chunk );
void extendMSA ();
void compressHash ();
void digestSHA256 ( uint8_t ** digest );
void initSHA256();
