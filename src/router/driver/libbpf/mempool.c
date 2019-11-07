// +build linux

#include <unistd.h>
#include <stdint.h>       // for uintptr_t

#include "mempool.h"

static inline int in_range(struct mempool *pool, uint64_t addr)
{
	uint64_t base = pool->base;
	uint64_t end = pool->base + pool->len*pool->room;
	uint64_t ptr = pool->base + addr;
	return base <= ptr && ptr <= end;
}

int push(struct mempool *pool, uint64_t addr)
{
	// unlikely
	if (pool->head == 0 || !in_range(pool, addr)) {
		// stack is full, can't push anymore elements
		// or the offset is not in mempool memory area range
		return -1;
	}

	pool->head++;
	pool->addr[pool->head] = addr;

	return pool->head;
}

// pop should be called after checking there's still element inside mempool
uint64_t pop(struct mempool *pool)
{
	// if (pool->head >= pool->len) {
	// 	// check if stack still has available elements
	// 	return NULL;
	// }
	return pool->addr[pool->head++];
}

struct mempool *mempool_create(uint64_t base, uint32_t len, uint32_t room)
{
	// create stack indexes
	uint64_t *addr = calloc(len, sizeof(*addr));
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
	for (uint64_t i = 0; i < len; i++) {
		addr[i] = i*room;
	}
	//   head                            len
	//   |                               |
	//   v                               v
	// [ (0*room) (1*room) (2*room) .... ((n-1)*room) ] // n elements

	return pool;

mem_pool_out:
	free(addr);

mem_stack_addr_out:

	return NULL;
}

int allocate(struct mempool *pool, uint64_t *bufs, uint32_t nb_pkts)
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

void release(struct mempool *pool, uint64_t *bufs, uint32_t nb_pkts)
{
	for (int i = 0; i < nb_pkts; i++) {
		push(pool, bufs[i]);
	}
}
