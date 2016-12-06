//OSv11 11464
// nwert

u32 copy_in_str(u8 *src, u32 len, u8 *dst, u32 maxlen);

typedef struct _drv_ctxt
{
	s8 name[0x40];
	u8 unk[4];
	u8 *save_area; //0x44
	struct _drv_ctxt *next;
} drv_ctxt_t;

u32 find_driver_by_name(s8 *name, drv_ctxt_t **ctxt, drv_ctxt_t **prev_ctxt)
{
	/* Sanitize name (toupper for every [a-z]). */
	spinlock_lock(&driver_ctxt_lock);
	/* Traverse driver list until name matches and fill ctxt and prev_ctxt accordingly. */
	return 0;
}

s32 KeDriverRegister(s8 *drvname, u32 drvnamelen, u32 *ptr1, u32 *ptr2);
s32 KeDriverDeregister(s8 *drvname, u32 drvnamelen);
s32 KeDriverCopyFromSaveArea(s8 *drvname, u32 drvnamelen, u8 *buf, u32 len);

s32 KeDriverCopyToSaveArea(s8 *drvname, u32 drvnamelen, u8 *buf, u32 len)
{
	s8 namebuf[0x40];
	drv_ctxt_t *drvctxt;
	
	//Copy driver name to local buffer.
	if(copy_in_str(drvname, drvnamelen, strbuf, 0x3F) == 0)
		return ERR;
	
	if(len > 0x1000)
		len = 0x1000;
	if(len != 0)
	{
		if((u32)buf < 0x1000 || (u32)buf >= 0xFFFFC000)
			return ERR;
		
		if(KeValidateAddrRange(1, (u32)buf, len) == 0)
			return ERR;
	}
	
	//Aquire driver_ctxt_lock, find driver, release driver_ctxt_lock (oooops).
	find_driver_by_name(namebuf, &drvctxt, NULL);
	spinlock_unlock(&driver_ctxt_lock);
	
	if(drvctxt == NULL)
		return ERR;
	
	//Allocate save area for driver context if required.
	if(drv_ctxt_t->save_area == NULL)
	{
		spinlock_lock(&kernel_work_area_heap_lock);
		heap_alloc(kernel_work_area_heap, 0x1000, 4, &ptr);
		spinlock_unlock(&kernel_work_area_heap_lock);
		if(ptr == NULL)
			return ERR;
		memset(ptr, 0, 0x1000);
		spinlock_lock(&driver_ctxt_lock);
		if(drvctxt->save_area == NULL)
		{
			drvctxt->save_area = ptr;
			ptr = NULL;
		}
		spinlock_unlock(&driver_ctxt_lock);
		if(ptr != NULL)
		{
			spinlock_lock(&kernel_work_area_heap_lock);
			heap_free(kernel_work_area_heap, ptr);
			spinlock_unlock(&kernel_work_area_heap_lock);
		}
	}
	
	//Copy data to save area.
	if(copy_in(buf, len, drvctxt->save_area) == 0)
		return ERR;
	return OK;
}
