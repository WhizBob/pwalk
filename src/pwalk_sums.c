#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ crc-32 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

// crc32() - Reads entire open file and calculates CRC-32 value.
// RETURNS: CRC value in passed variable, bytes processed as function value.
// NOTE: Caller should assume result is valid iff returned size matches file's size.
// MT-safe.

size_t
crc32(int fd, char *rbuf, int rbuf_size, unsigned *crc_val)
{
   size_t nbytes, nbytes_t;

   nbytes_t = 0;
   while ((nbytes = pread(fd, rbuf, rbuf_size, nbytes_t)) > 0) {
      nbytes_t += nbytes;
   }
   *crc_val = 0xdeadbeef ^ nbytes_t;
   return(nbytes_t);
}

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ crc-16 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

// crc16() - Calculate CRC-16 for passed buffer

unsigned short
crc16(const unsigned char *data_p, int length)
{
   unsigned char x;
   unsigned short crc = 0xFFFF;

   while (length--) {
      x = crc >> 8 ^ *data_p++;
      x ^= x>>4;
      crc = (crc << 8) ^ ((unsigned short)(x << 12)) ^ ((unsigned short)(x <<5)) ^ ((unsigned short)x);
   }
   return crc;
}
