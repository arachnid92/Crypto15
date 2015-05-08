#include <stdint.h>

uint32_t rotateRight ( uint32_t x, uint32_t i );
uint32_t Ch ( uint32_t x, uint32_t y, uint32_t z );
uint32_t Maj ( uint32_t x, uint32_t y, uint32_t z );
uint32_t BigSigma0( uint32_t x );
uint32_t BigSigma1( uint32_t x );
uint32_t SmallSigma0( uint32_t x );
uint32_t SmallSigma1( uint32_t x );

uint32_t bytes2Int ( uint8_t h, uint8_t m1, uint8_t m2, uint8_t l);
uint8_t long2Byte ( uint64_t l, uint8_t pos );
uint8_t int2Byte ( uint32_t i, uint8_t pos );

void feedByteSHA256 ( uint8_t byte, uint8_t done );
void initSHA256 ();
void padChunk();
void processChunk();
void prepareMessageSchedule();
uint8_t getByteFromHashSHA256( uint8_t pos );
