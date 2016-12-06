//OSv11 11464
// nwert

/*! IOS commands. */
#define IOS_CMD_OPEN 1
#define IOS_CMD_CLOSE 2
#define IOS_CMD_READ 3
#define IOS_CMD_WRITE 4
#define IOS_CMD_SEEK 5
#define IOS_CMD_IOCTL 6
#define IOS_CMD_IOCTLV 7

/*! ioctlv entry. */
typedef struct _ioctlv_ent
{
	u32 phys;
	u32 size;
	u32 virt;
} ioctlv_ent_t;

/*! IOS packet. */
typedef struct _ios_packet
{
	u32 _0_cmd;
	u32 _4; //unk
	u32 _8_fd;
	u32 _C; //unk
	u32 _10_coreid;
	u32 _14_rampid; //rampid
	u32 _18_tidhi; //titleid
	u32 _1C_tidlo; //titleid
	u32 _20; //unk
	union
	{
		struct
		{
			u32 _24;
			u32 _28;
			u32 _2C;
			u32 _30;
			u32 _34;
		};
		struct
		{
			u32 fname;
			u32 namelen;
		} open;
		struct
		{
		} close;
		struct
		{
			u32 buf;
			u32 size;
		} readwrite;
		struct
		{
			u32 where;
			u32 whence;
		} seek;
		struct
		{
			u23 cmd;
			u32 buf_in;
			u32 size_in;
			u32 buf_out;
			u32 size_out;
		} ioctl;
		struct
		{
			u32 cmd;
			u32 num_in;
			u32 num_out;
			u32 vec;
		} ioctlv;
	} args;
	u32 _38_cmd;
	u32 _3C_fd;
	union
	{
		struct
		{
			u32 _40;
			u32 _44;
		};
		struct
		{
			u32 fname;
		} open;
		struct
		{
			u32 buf;
		} readwrite;
		struct
		{
			u32 buf_in;
			u32 buf_out;
		} ioctl;
		struct
		{
			ioctlv_ent_t *vec;
		} ioctlv;
	} virt;
	//sizeof(ios_packet_t) = 0x48
} ios_packet_t;

typedef struct _ios_ctxt
{
	u32 _0;
	u32 _4;
	u32 _8;
	u32 _C;
	ios_packet_t *pkt;
} ios_ctxt_t;

typedef struct _ios_fd_ctxt
{
	u32 unk;
	u32 *bitmap;
	u32 num_used;
	u32 num_total;
} ios_fd_ctxt_t;

u32 verify_external_fd(u32 fd, u32 rampid)
{
	ios_fd_ctxt_t *ctxt_table = (ios_fd_ctxt_t *)0xFFE85A20;

	r11 = rlwinm(fd, 0, 1, 3);
	if(r11 != 0x10000000)
		return 0xEAFE0BAD;
	
	ios_fd_ctxt_t *r10 = &ctxt_table[rampid];
	idx = fd & 0xFF;
	if(idx < r10->num_total)
		return idx;
	
	return 0xEAFE0BAD;
}

u32 packet_set_real_fd(ios_pcket_t *pkt, u32 rampid)
{
	if(pkt->_8_fd < 0)
		return 1;
	
	u32 res = 0;
	
	spinlock_lock(IPCK_driver_lock);
	
	r11 = pkt->_8_fd ^ 0xEAFE0BAD;
	idx = verify_external_fd(clrlwi(r11, 1), rampid);
	if(idx != 0xEAFE0BAD)
	{
		u32 *fd_table = (u32 *)(rampid*0x180 + 0xFFE85B60);
		*pkt->_8_fd = fd_table[idx];
		res = 1;
	}
	
	spinlock_unlock(IPCK_driver_lock);
	
	return res;
}

s32 inspect_fixup_IPC_packet(addrctxt:r3, ios_ctxt_t *ctxt, is_loader:r5)
{
	ios_packet_t *pkt = ctxt->pkt; //r31
	
	pkt->_3C_fd = pkt->_8_fd;
	pkt->_C = 0;
	pkt->_4 = 0;
	pkt->_10_coreid = PPC_SPR_PIR + 1;
	
	rampid = GET_RAMPID;
	
	if(r5 == 0)
	{
		pkt->_14_rampid = rampid;
		pkt->_181C_titleid = /*u64*/get_title_id(sub_FFF10B98(0));
	}
	
	u32 cmd = pkt->_0_cmd;
	pkt->_38_cmd = cmd;
	
	if(cmd < 1)
		return -0x1D;
	
	switch(cmd)
	{
	case IOS_CMD_OPEN: //1
		pkt->_3C_fd = 0;
		if(pkt->args.open.namelen >= 0x20)
			return -0x1D;
		pkt->args.open.filename = KiEffectiveToPhysical(addrctxt, pkt->virt.open.fname);
		if(IPCKDriver_CheckAddress(ctxt, pkt->args.open.fname, pkt->args.open.namelen) == 0)
			return -0x1D;
		return 0;
		break;
	case IOS_CMD_CLOSE: //2
	case IOS_CMD_SEEK: //5
		if(r5 == 0)
			if(packet_set_real_fd(pkt, rampid) == 0)
				return -0x1D;
		return 0;
		break;
	case IOS_CMD_READ: //3
	case IOS_CMD_WRITE: //4
		if(r5 == 0)
			if(packet_set_real_fd(pkt, rampid) == 0)
				return -0x1D;
		pkt->args.readwrite.buf = KiEffectiveToPhysical(addrctxt, pkt->virt.readwrite.buf);
		if(IPCKDriver_CheckAddress(ctxt, pkt->args.readwrite.buf, pkt->args.readwrite.size) == 0)
			return -0x1D;
		return 0;
		break;
	case IOS_CMD_IOCTL: //6
		if(r5 == 0)
			if(packet_set_real_fd(pkt, rampid) == 0)
				return -0x1D;
		pkt->args.ioctl.buf_out = KiEffectiveToPhysical(addrctxt, pkt->virt.ioctl.buf_out);
		if(IPCKDriver_CheckAddress(ctxt, pkt->args.ioctl.buf_out, pkt->args.ioctl.size_out) == 0)
			return -0x1D;
		pkt->args.ioctl.buf_in = KiEffectiveToPhysical(addrctxt, pkt->virt.ioctl.buf_in);
		if(IPCKDriver_CheckAddress(ctxt, pkt->args.ioctl.buf_in, pkt->args.ioctl.size_in) == 0)
			return -0x1D;
		return 0;
		break;
	case IOS_CMD_IOCTLV: //7
		if(r5 == 0)
			if(packet_set_real_fd(pkt, rampid) == 0)
				return -0x1D;
		{
			u32 idx = 0;
			while(1)
			{
				if(idx > pkt->args.ioctlv.num_out)
					break;
				ioctlv_ent_t *ent = &pkt->virt.ioctlv.vec[pkt->args.ioctlv.num_in + idx];
				r4 = ent->virt;
				if(r4 == 0)
				{
					if(ent->size != 0)
						return -0x1D;
				}
				else
					r4 = KiEffectiveToPhysical(addrctxt, r4);
				ent->phys = r4;
				if(IPCKDriver_CheckAddress(ctxt, r4, ent->size) == 0)
					return -0x1D;
				idx++;
			}
			
			idx = 0;
			while(1)
			{
				if(idx >= pkt->args.ioctlv.num_in)
					break;
				ioctlv_vec_t *ent = &pkt->virt.ioctlv.vec[idx];
				r4 = ent->virt;
				if(r4 == 0)
				{
					if(ent->size != 0)
						return -0x1D;
				}
				else
					r4 = KiEffectiveToPhysical(addrctxt, r4);
				ent->phys = r4;
				if(IPCKDriver_CheckAddress(ctxt, r4, ent->size) == 0)
					return -0x1D;
				idx++;
			}
			
			u32 len = (pkt->args.ioctlv.num_out + pkt->args.ioctlv.num_in)*sizeof(ioctlv_ent_t);
			FlushDataRangeNoSync((u32)pkt->virt.ioctlv.vec, len);
			r4 = KiEffectiveToPhysical(addrctxt, (u32)pkt->virt.ioctlv.vec);
			pkt->args.ioctlv.vec = r4;
			if(IPCKDriver_CheckAddress(ctxt, r4, len)) == 0)
					return -0x1D;
			return 0;
		}
		break;
	default:
		return -0x1D;
	}
	
	return -0x1D;
}
