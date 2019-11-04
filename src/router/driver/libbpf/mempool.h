// +build linux

#ifndef __GLASNOSTIC_MEMPOOL_H__
#define __GLASNOSTIC_MEMPOOL_H__

#include <stdlib.h>

struct mempool {
	void *base;        // point to base memory address;
	size_t room;       // size of each data room;
	int len;           // total number of stack elements

	// stack implement
	int *addr;         // stack pointer, store index of umem buffers
	int head;          // current head pointer
};

struct mempool *mempool_create(void *base, size_t len, size_t room);
void release(struct mempool *pool, void **bufs, size_t nb_pkts);
int allocate(struct mempool *pool, void **bufs, size_t nb_pkts);
void *pop(struct mempool *pool);
int push(struct mempool *pool, void *addr);

#endif //__GLASNOSTIC_MEMPOOL_H__
