#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef RANDOM_BYTE_H
#define RANDOM_BYTE_H

void
randombytes(unsigned char *x, unsigned long long xlen);

#endif
