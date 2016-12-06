//OSv11 11464
// nwert

typedef struct _heap_ctxt
{
	u32 base;
	u32 end;
	s32 first_idx;
	s32 last_idx;
	u32 _10;
} heap_ctxt_t;
//sizeof(heap_ctxt_t) = 0x14

typedef struct _heap_block
{
	u32 addr;
	s32 size; //< 0 means free
	s32 prev_idx;
	s32 next_idx;
} heap_block_t;
//sizeof(heap_block_t) = 0x10

s32 _find_containing_block(heap_ctxt_t *heap, u32 addr)
{
	if(addr < heap->base)
		return -1;
	if(addr >= heap->end)
		return -1;
	
	r12 = addr - heap->base;
	r11 = heap->end - addr;
	if(r11 >= r12)
	{
		r12 = heap->first_idx;
		while(1)
		{
			heap_block_t *blk = (heap + sizeof(heap_ctxt_t) + r12 * sizeof(heap_block_t));
			if(addr < blk->addr + abs(blk->size))
				return r12;
			r12 = blk->next_idx;
			if(r12 == -1)
				break;
		}
	}
	else
	{
		r12 = heap->last_idx;
		while(1)
		{
			heap_block_t *blk = (heap + sizeof(heap_ctxt_t) + r12 * sizeof(heap_block_t));
			if(addr >= blk->addr)
				return r12;
			r12 = blk->prev_idx;
			if(r12 == -1)
				break;
		}
	}
	
	return -1;
}

void _heap_free(heap_ctxt_t *heap, s32 block)
{
	r11 = (u32)heap + sizeof(heap_ctxt_t);
	heap_block_t *r8 = r11 + block * sizeof(heap_block_t);
	r7 = r8->prev_idx;
	
	if(r7 != -1)
	{
		heap_block_t *r9 = r11 + r7 * sizeof(heap_block_t);
		r10 = r9->size;
		if(r10 < 0)
		{
			r9->size = r10 - r8->size;
			r12 = r8->next_idx;
			r9->next_idx = r12;
			if(r12 == -1)
				heap->last_idx = r7;
			else
			{
				heap_block_t *r12 = r11 + r12 * sizeof(heap_ctxt_t);
				r12->prev_idx = r7;
			}
			r10 = heap->_10;
			if(r10 != -1)
			{
				heap_block_t *r12 = r11 + r10 * sizeof(heap_block_t);
				r12->prev_idx = block;
			}
			r8->next_idx = r10;
			r8->prev_idx = -1;
			heap->_10 = block;
			block = r7;
		}
		else
			goto loc_FFF1CCF8;
	}
	else
	{
		loc_FFF1CCF8:;
		r8->size = -r8->size;
	}
	
	heap_block_t *r8 = r11 + block * sizeof(heap_block_t);
	r7 = r8->next_idx;
	if(r7 == -1)
		return;
	
	heap_block_t *r9 = r11 + r7 * sizeof(heap_block_t);
	r10 = r9->size;
	if(r10 >= 0)
		return;
	
	r8->size += r10;
	r12 = r9->next_idx;
	r8->next_idx = r12;
	if(r12 == -1)
		heap->last_idx = block;
	else
	{
		heap_block_t *r12 = r11 + r12 * sizeof(heap_block_t);
		r12->prev_idx = block;
	}
	
	r10 = heap->_10;
	if(r10 != -1)
	{
		heap_block_t *r12 = r11 + r10 * sizeof(heap_block_t);
		r12->prev_idx = r7;
	}
	
	r9->next_idx = r10;
	r9->prev_idx = -1;
	heap->_10 = r7;
}

void heap_free(heap_ctxt_t *heap, u32 addr)
{
	s32 bidx = _find_containing_block(heap, addr);
	if(bidx == -1)
		return;
	
	heap_block_t *blk = (u32)heap + sizeof(heap_ctxt_t) + bidx * sizeof(heap_block_t);
	if(blk->addr != addr) //Check addr.
		return;
	if(blk->size < 0) //Not allocated?
		return;
	
	_heap_free(heap, res);
}

void _heap_alloc_at()
{
}

void *heap_alloc()
{
}

//hdr_size is usually some aligned value + 0x30.
void heap_create(void *space, u32 hdr_size, void *base, u32 size)
{
	blk_cnt = 0;
	if(hdr_size > 0x40)
	{
		blk_size = hdr_size - 0x30;
		blk_cnt = blk_size / sizeof(heap_block_t);
	}
	
	if(blk_cnt <= 0 || r6 <= 0)
		return 0xFFF810BF;
	
	end = base + size;
	if(end < base)
		return 0xFFF810BF;
	
	heap_ctxt_t *heap = (heap_ctxt_t *)space;
	heap->base = base;
	heap_block_t *r27 = space + sizeof(heap_ctxt_t);
	memset(r27, 0, blk_cnt * sizeof(heap_block_t));
	heap->end = end;
	
	bidx = 1;
	while(bidx < blk_cnt)
	{
		heap_block_t *blk = r27 + bidx;
		blk->prev_idx = bidx - 1;
		bidx++;
		blk->next_idx = bidx;
	}
	
	(r27 + 1)->prev_idx = -1;
	(r27 + blk_cnt - 1)->next_idx = -1;
	
	heap->_10 = 1;
	r27->addr = base;
	r27->size = -size;
	r27->prev_idx = -1;
	r27->next_idx = -1;
	heap->first_idx = 0;
	heap->last_idx = 0;
	
	return 0;
}
