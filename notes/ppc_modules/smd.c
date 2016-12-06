// Reversing of smd.c of coreinit.rpl
// Looks like a usermode IOSU IPC implementation?
// plutoo

smd_context* smdPpcInit(ctx_ptr, ctx_size, table1_num_words, table0_start, mutex_ptr)
{
    if(ctx_ptr == 0 || table1_num_words == 0 || table0_start == 0)
        return 0;

    smd_context = ROUND_UP(ctx_ptr, 4);
    table0 = ROUND_UP(smd_context + 0x48, 0x40);
    table1 = ROUND_UP(table0 + 0x600, 0x40);
    table1_num_words++;
    table2 = ROUND_UP(table1 + (table1_num_words<<8), 0x40);

    if((table2 + (table1_num_words<<8)) > (ctx_ptr+ctx_size))
        return 0;

    if( *(u32*) smd_context == smd_context )
        seq_counter = *(u32*)(table0 + 0x10);
    else
        seq_counter = 0;

    memset(ctx_ptr, 0, ctx_size);

    *(u32*)(smd_context+0x38) = table1_num_words;
    *(u32*)(smd_context+0x3C) = table1;
    *(u32*)(smd_context+0x40) = table2;
    *(u32*)(smd_context+0x44) = 1;

    *(u32*)smd_context = smd_context;
    *(u32*)(smd_context+4) = table0;
    *(u32*)(smd_context+8) = mutex_ptr;

    if(mutex_ptr != 0)
        OSInitMutex(mutex_ptr);
    else
        OSInitMutex((_Mutex*) (smd_context + 0xC));

    found_null_byte = 0;
    
    for(i=0; i<0x10; i++) {
        r7 = *(u8*) table0_start++;
        *(u8*) table0++ = r7;

        if(r7 == 0)
            break;
    }

    *(u32*)(table0 + 0x10) = seq_counter + 1;

    *(u32*)(table0 + 0x80) = 0x1111;
    *(u32*)(table0 + 0x100) = table1_num_words;
    *(u32*)(table0 + 0x180) = 0;
    *(u32*)(table0 + 0x200) = 0;
    *(u32*)(table0 + 0x280) = OSEffectiveToPhysical( *(u32*) (smd_context+0x3C) );

    DCFlushRangeNoSync( *(u32*) (smd_context+0x3C), 4*table1_num_words );
    __builtin_sync();
    __builtin_eieio();

    *(u32*)(table0 + 0x340) = 0x1111;
    *(u32*)(table0 + 0x3C0) = table1_num_words;
    *(u32*)(table0 + 0x440) = 0;
    *(u32*)(table0 + 0x4C0) = 0;
    *(u32*)(table0 + 0x540) = OSEffectiveToPhysical( *(u32*) (smd_context+0x40) );

    DCFlushRangeNoSync( *(u32*) (smd_context+0x40), 4*table1_num_words );
    __builtin_sync();
    __builtin_eieio();

    DCFlushRangeNoSync(table0, 0x600);
    __builtin_sync();
    __builtin_eieio();

    return smd_context;
}

static void smdCriticalSectionBegin(type, ptr) {
    if(type == 0)
        OSLockMutex(ptr);
    else if(type == 1)
        *(u32*)ptr = OSDisableInterrupts();
}

static void smdCriticalSectionEnd(type, ptr) {
    if(type == 0)
        OSUnlockMutex(b);
    else if(type == 1)
        OSRestoreInterrupts(*(u32*)b);
}

int smdPpcOpen(smd_context) {
    if(*(u32*) smd_context != smd_context)
        return 0xFFF3FFFD;

    smdCriticalSectionBegin(*(u32*)(smd_context+8), smd_context+0xC);

    if(*(u32*)(smd_context+0x44) > (signed) 0) {
        table0 = *(u32*)(smd_context+4);

        *(u32*)(table0 + 0x340) = 0x2222;

        DCFlushRangeNoSync(table0, 4);
        __builtin_sync();
        __builtin_eieio();

        *(u32*)(smd_context+0x44) = 3;
        smdCriticalSectionEnd(*(u32*)(smd_context+8), smd_context+0xC);
        return 0;
    }

    smdCriticalSectionEnd(*(u32*)(smd_context+8), smd_context+0xC);
    return 0xFFF3FFF3;
}

int smdPpcClose(smd_context) {
    if(*(u32*) smd_context != smd_context)
        return 0xFFF3FFFD;

    smdCriticalSectionBegin(*(u32*)(smd_context+8), smd_context+0xC);
    
    if(*(u32*)(smd_context+0x44) > (signed) 0) {
        table0 = *(u32*)(smd_context+4);

        *(u32*)(table0 + 0x340) = 0x3333;

        DCFlushRangeNoSync(table0, 4);
        __builtin_sync();
        __builtin_eieio();

        *(u32*)(smd_context+0x44) = 2;
        smdCriticalSectionEnd(*(u32*)(smd_context+8), smd_context+0xC);
        return 0;
    }

    smdCriticalSectionEnd(*(u32*)(smd_context+8), smd_context+0xC);
    return 0xFFF3FFF2;
}

int smdPpcGetCtrlTableVectors(smd_context, out_ptr) {
    if(*(u32*) smd_context != smd_context)
        return 0xFFF3FFFD;

    if(*(u32*)(smd_context+0x44) > (signed) 0) {
        *(u32*) out_ptr       = *(u32*)(smd_context+4);
        *(u32*)(out_ptr+4)    = 0x600;
        *(u32*)(out_ptr+8)    = *(u32*)(smd_context+0x3C);
        *(u32*)(out_ptr+0xC)  = *(u32*)(smd_context+0x38) << 8;
        *(u32*)(out_ptr+0x14) = *(u32*)(smd_context+0xC);
        return 0;
    }

    return 0xFFF3FFF3;
}

int smdPpcGetInterfaceState(smd_context, out0_ptr, out1_ptr) {
    if(*(u32*) smd_context != smd_context)
        return 0xFFF3FFFD;

    if(*(u32*)(smd_context+0x44) > (signed) 0) {
        table0 = *(u32*)(smd_context+4);

        if(out1_ptr != 0) {
            DCInvalidateRange(table0+0x80, 4);
            *(u32*) out1_ptr = *(u32*)(table0+0x80);
        }
        if(out0_ptr != 0) {
            DCInvalidateRange(table0+0x340, 4);
            *(u32*) out0_ptr = *(u32*)(table0+0x340);
        }

        return 0;
    }

    return 0xFFF3FFF3;
}

static int smdPpcSetMessage(smd_context, type, buf, size) {
    table0 = *(u32*)(smd_context+4);
    r28 = table0 + 0x80;

    DCInvalidateRange(r28, 0x280);
    if(smdUnknown(r28) <= (signed) 1)
        return 0xFFF3FFFC;

    r10 = *(u32*)(smd_context+0x3C) + (*(u32*)(table0+0x180) << 8);

    *(u32*) r10    = type;
    *(u32*)(r10+4) = size;
    memcpy(r10 + 8, buf, size);

    DCFlushRangeNoSync(smd_context, 0x100);
    __builtin_sync();
    __builtin_eieio();

    // Increment modulo
    *(u32*)(table0+0x180) = (*(u32*)(table0+0x180)+1) % (*(u32*)(table0+0x80));

    DCFlushRangeNoSync(table0+0x180, 4);
    __builtin_sync();
    __builtin_eieio();
}


int smdPpcSendMessage(smd_context, buf, size) {
    if(*(u32*) smd_context != smd_context)
        return 0xFFF3FFFD;

    smdCriticalSectionBegin(*(u32*)(smd_context+8), smd_context+0xC);

    if(*(u32*)(smd_context+0x44) != 3) {
        smdCriticalSectionEnd(*(u32*)(smd_context+8), smd_context+0xC);
        return 0xFFF3FFF2;
    }

    if(size > (unsigned) 0x80) {
        smdCriticalSectionEnd(*(u32*)(smd_context+8), smd_context+0xC);
        return 0xFFF3FFFF;
    }

    int ret = smdPpcSetMessage(smd_context, 0, buf, size);

    smdCriticalSectionEnd(*(u32*)(smd_context+8), smd_context+0xC);
    return ret;
}

// XXX: smdPpcReceive
// XXX: smdPpcSendVector
// XXX: smdPpcSendVectorSpec
