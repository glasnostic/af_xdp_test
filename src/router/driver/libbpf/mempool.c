// +build linux

#include <unistd.h>
#include <stdint.h>       // for uintptr_t

#include "mempool.h"

static inline void *mem_addr(struct mempool *pool, int idx)
{
	return (void*)(uint64_t)(pool->base + idx*pool->room);
}

static inline int mem_index(struct mempool *pool, void *addr)
{
	return ((uint64_t)addr - (uint64_t)pool->base ) / pool->room;
}

static inline int in_range(struct mempool *pool, void *addr)
{
	uint64_t base = (uint64_t)pool->base;
	uint64_t end = (uint64_t)pool->base + pool->len*pool->room;
	uint64_t ptr = (uint64_t)addr;
	return base <= ptr && ptr <= end;
}

int push(struct mempool *pool, void *addr)
{
	if (pool->head == 0 || !in_range(pool, addr)) {
		// stack is full, can't push anymore elements
		// or the addr is not in mempool memory area range
		return -1;
	}

	pool->head++;
	pool->addr[pool->head] = mem_index(pool, addr);

	return pool->head;
}

void *pop(struct mempool *pool)
{
	if (pool->head >= pool->len) {
		// check if stack still has available elements
		return NULL;
	}
	return mem_addr(pool, pool->addr[pool->head++]);
}

struct mempool *mempool_create(void *base, size_t len, size_t room)
{
	// create stack indexes
	int *addr = calloc(len, sizeof(*addr));
	if (!addr) {
		goto mem_stack_addr_out;
	}

	struct mempool *pool = calloc(1, sizeof(*pool));
	if (!pool) {
		goto mem_pool_out;
	}

	// init pool contents
	pool->base = base;
	pool->room = room;

	// init stack contents
	pool->addr = addr;
	pool->head = 0;
	pool->len = len;

	// init memstack struct with stack indexes
	for (int i = 0; i < len; i++) {
		addr[i] = i;
	}
	//   head       len
	//   |          |
	//   v          v
	// [ 0 1 2 .... n-1 ] // n elements

	return pool;

mem_pool_out:
	free(addr);

mem_stack_addr_out:

	return NULL;
}

int allocate(struct mempool *pool, void **bufs, size_t nb_pkts)
{
	if ((pool->len - pool->head) < nb_pkts) {
		// not enough buffers in mempool
		return 0;
	}

	for (int i = 0; i < nb_pkts; i++) {
		bufs[i] = pop(pool);
	}

	return nb_pkts;
}

void release(struct mempool *pool, void **bufs, size_t nb_pkts)
{
	for (int i = 0; i < nb_pkts; i++) {
		push(pool, bufs[i]);
	}
}
