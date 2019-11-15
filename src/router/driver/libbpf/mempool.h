// +build linux

#ifndef __GLASNOSTIC_MEMPOOL_H__
#define __GLASNOSTIC_MEMPOOL_H__

#include <stdlib.h>

struct mempool {
	uint64_t base;        // point to base memory address;
	uint32_t room;        // size of each data room;
	uint32_t len;         // total number of stack elements

	// stack implement
	uint64_t *addr;         // stack pointer, store index of umem buffers
	int head;          // current head pointer
};

struct mempool *mempool_create(uint64_t base, uint32_t len, uint32_t room);
void release(struct mempool *pool, uint64_t *bufs, uint32_t nb_pkts);
int allocate(struct mempool *pool, uint64_t *bufs, uint32_t nb_pkts);
uint64_t pop(struct mempool *pool);
int push(struct mempool *pool, uint64_t addr);

#endif //__GLASNOSTIC_MEMPOOL_H__
