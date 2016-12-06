#ifndef _AUXVEC_H_
#define _AUXVEC_H_

typedef struct
{
	int a_type;
	union
	{
		int a_val;
	} a_un;
} __attribute__((packed)) Elf32_auxv_t;

#define AT_NULL 0
#define AT_ENTRY 9
#define AT_UID 11

#endif
