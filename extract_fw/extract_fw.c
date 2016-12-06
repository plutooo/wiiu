// Extract user processes from fw.elf for analysis in IDA.
// - plutoo

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include <elf.h>
#ifdef __CYGWIN__
#include "auxvec.h"
#else
#include <linux/auxvec.h>
#endif

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;


static FILE* fd;
static FILE* py;
static FILE* out;
static Elf32_Ehdr hdr;

static int dump_segments = 0;
static int pid = -1;
static u32 entry = -1;
static u32 unk0  = -1;
static u32 stack_sz = -1;
static u32 stack_ptr  = -1;
static u32 unk3  = -1;


#define MAX_SEGMENTS 32
static struct {
    u32 vaddr;
    u32 size;
    u32 flags;
    u8* buffer;
} segments[MAX_SEGMENTS];
static u32 num_segments = 0;


#define MAX_SYSCALL 0x100
static struct {
    const char* name;
    u32 num_args;
	u32 idx;
} syscalls_meta[MAX_SYSCALL] =
{
    {"CreateThread", 4+2}, // @+0
    {"JoinThread", 2},
    {"DestroyThread", 2},
    {"GetCurrentThreadId", 0},
    {NULL, 0},
    {"GetCurrentProcessId", 0},
    {"GetProcessName", 2},
    {"StartThread", 1},
    {"StopThread", 1},
    {"YieldThread", 1},
    {"GetThreadPriority", 1},
    {"SetThreadPriority", 2},
    {"CreateMessageQueue", 2},
    {"DestroyMessageQueue", 1},
    {"SendMessage", 3},
    {"JamMessage", 3},
    {"ReceiveMessage", 3},
    {"RegisterEventHandler", 3},
    {"UnregisterEventHandler", 1},
    {"CreateTimer", 4},
    {"RestartTimer", 3},
    {"StopTimer", 1},
    {"DestroyTimer", 1},
    {NULL, 0},
    {"TimeNow", 0},
    {"GetUpTimeStruct", 1},
    {"GetUpTime64", 1},
    {NULL, 1},
    {"GetAbsTimeCalendar", 1},
    {"GetAbsTime64", 1},
    {"GetAbsTimeStruct", 1},
    {"SetProcessDebugFlag", 2},
    {"ReadOtpBlk20", 0}, // @+0x20
    {"GetJtagStatus", 0},
    {"ReadOtp", 3},
    {"CreateHeap", 2},
    {"CreateLocalProcessHeap", 2},
    {"CreateCrossProcessHeap", 1},
    {"DestroyLocalProcessHeap", 1},
    {"Alloc", 2},
    {"AllocAligned", 3},
    {"Free", 2},
    {NULL, 2},
    {NULL, 3},
    {"CreateDevice", 2},
    {"RegisterDevice", 2},
    {NULL, 2},
    {NULL, 3},
    {NULL, 0},
    {NULL, 3},
    {"QueryFeature", 3},
    {"Open", 2},
    {"Close", 1},
    {"Read", 3},
    {"Write", 3},
    {"Seek", 4},
    {"Ioctl", 6},
    {"Ioctlv", 5},
    {"OpenAsync", 4},
    {"CloseAsync", 3},
    {"ReadAsync", 5},
    {"WriteAsync", 5},
    {"SeekAsync", 5},
    {"IoctlAsync", 8},
    {"IoctlvAsync", 7}, // @+0x40
    {"OpenAsAsync", 6},
    {"WriteAsAsync", 7},
    {NULL, 3},
    {NULL, 3},
    {NULL, 5},
    {NULL, 5},
    {NULL, 5},
    {NULL, 7},
    {"ResourceReply", 2},
    {NULL, 4},
    {NULL, 3},
    {NULL, 1},
    {NULL, 1},
    {NULL, 1},
    {NULL, 1},
    {NULL, 1},
    {"EnableIrqEvent", 1},
    {"Stub0", 0},
    {NULL, 2},
    {NULL, 1},
    {"Stub1", 0},
    {"Stub2", 0},
    {NULL, 2},
    {NULL, 2},
    {NULL, 2},
    {"ValidateIobAddress", 1},
    {"InvalidateDCache", 2},
    {"FlushDCache", 2},
    {NULL, 1},
    {"GetKernelVersionA", 2},
    {"GetKernelVersionB", 2},
    {NULL, 1}, // @+0x60
    {"CreateMutex", 2},
    {"AcquireMutex", 2},
    {"ReleaseMutex", 1},
    {"DestroyMutex", 1},
    {NULL, 0},
    {"ContinueStartup", 0},
    {NULL, 3},
    {"ValidatePowerPCRange", 2},
    {NULL, 0},
    {"GetCpuUtilization", 0},
    {NULL, 2},
    {"StartProfile", 2},
    {NULL, 1},
    {NULL, 2},
    {NULL, 2},
    {NULL, 2},
    {NULL, 2},
    {"GetMsgQueueStats", 1},
    {"GetResourceAggregateUtilizationStats", 2},
    {"GetProcessResourceAllocationStats", 3},
    {"GetTimerStats", 1},
    {"GetMutexStats", 1},
    {"GetHeapStats", 2},
    {NULL, 1},
    {NULL, 1},
    {"UpdateDebuggerReg", 0},
    {"ZeroDebuggerReg", 0},
    {"WriteDebuggerReg", 1},
    {"IsDebuggerAttached", 2},
    {"AnotherPanic", 1},
    {"Panic", 2},
    {NULL, 0}, // @+0x80
    {NULL, 1},
    {NULL, 1},
    {NULL, 2},
    {NULL, 5},
    {NULL, 1},
    {NULL, 0},
    {NULL, 3},
    {NULL, 1},
    {NULL, 0},
    {NULL, 2},
    {NULL, 4},
    {NULL, 2},
    {"Stub3", 0},
    {"GetResourceViolations", 2},
    {NULL, 1},
    {NULL, 1},
    {"GetProcessPendingResourceRequests", 3},
    {NULL, 0},
    {"PokeDi", 0}
};


static u32 be32(u32 num)
{
    return ((num>>24)&0xff) | ((num<<8)&0xff0000) | ((num>>8)&0xff00) |
        ((num<<24)&0xff000000);
}

static u16 be16(u16 num)
{
    return ((num<<8)&0xff00) | ((num>>8)&0xff);
}

static int check_elf_header()
{
    return (hdr.e_ident[0] == ELFMAG0) && (hdr.e_ident[1] == ELFMAG1) &&
        (hdr.e_ident[2] == ELFMAG2) && (hdr.e_ident[3] == ELFMAG3);
}

static int find_aux_info()
{
    u32 i;
    for(i=0; i<hdr.e_phnum; i++)
    {
        if(fseek(fd, hdr.e_phoff + i*hdr.e_phentsize, SEEK_SET) != 0)
        {
            perror("fseek");
            return 1;
        }

        Elf32_Phdr phdr;

        if(fread(&phdr, sizeof(phdr), 1, fd) != 1)
        {
            perror("fread1");
            return 1;
        }

        /* Look for the PT_NOTE header. */
        if(be32(phdr.p_type) == PT_NOTE)
        {
            if(fseek(fd, be32(phdr.p_offset)+12, SEEK_SET) != 0)
            {
                perror("fseek");
                return 1;
            }

            u32 size = be32(phdr.p_filesz)-12;
            u32 pos = 0;
            int found_pid = 0;

            /* Look through the auxillary headers. */
            while(pos < size)
            {
                Elf32_auxv_t aux;

                if(fread(&aux, sizeof(aux), 1, fd) != 1)
                {
                    perror("fread2");
                    return 1;
                }

                pos += sizeof(aux);

                aux.a_type = be32(aux.a_type);
                aux.a_un.a_val = be32(aux.a_un.a_val);

                switch(aux.a_type)
                {
                case AT_NULL:
                    break;
                case AT_UID:
                    if(aux.a_un.a_val == pid) {
                        if(found_pid)
                            return 0;

                        found_pid = 1;
                    }
                    break;
                case AT_ENTRY:
                    if(found_pid) {
                        printf("Entrypoint for pid %d: %08x\n", pid, aux.a_un.a_val);
                        entry = aux.a_un.a_val;
                    }
                    break;
                case 0x7D:
                    if(found_pid)
                        unk0 = aux.a_un.a_val;
                    break;
                case 0x7E:
                    if(found_pid) {
                        printf("Stacksize for pid %d: %08x\n", pid, aux.a_un.a_val);
                        stack_sz = aux.a_un.a_val;
                    }
                    break;
                case 0x7F:
                    if(found_pid) {
                        stack_ptr = aux.a_un.a_val;
                        printf("Mainstack for pid %d: %08x\n", pid, aux.a_un.a_val);
                    }
                    break;
                case 0x80:
                    if(found_pid)
                    {
                        unk3 = aux.a_un.a_val;
                        goto end_loop;
                    }
                    break;
                default:
                    printf("Unknown AUX type 0x%x.\n", aux.a_type);
                    return 1;
                }
                continue;

            end_loop:
                break;
            }

            if(!found_pid)
            {
                printf("Failed to find pid %d..\n", pid);
                return 1;
            }

            /* Success. */
            return 0;
        }
    }

    printf("Didn't find PT_NOTE..\n");
    return 1;
}

static void fix_und_instructions(u32* buf, u32 size, u32 addr)
{
    u32 i;
    for(i=0; i<size/4 - 1; i++)
    {
        u32 insn = be32(buf[i]);
        u32 bxlr = be32(buf[i+1]);
        if((insn & 0xFFFF00FF) == 0xE7F000F0 && bxlr == 0xE12FFF1E)
        {
            u32 num = (insn>>8) & 0xFF;
            fprintf(py, "idc.SetType(0x%08x, 'int sc_%02x(", addr+4*i, num);

            int first = 1;
            u32 j;
            for(j=0; j<syscalls_meta[num].num_args; j++)
            {
                if(first)
                    first = 0;
                else
                    fprintf(py, ",");

                fprintf(py, "int");
            }
            fprintf(py, ")')\n");

            if(syscalls_meta[num].name != NULL)
                fprintf(py, "idc.MakeName(0x%08x, 'syscall_%s_%d')\n", addr+4*i,
                    syscalls_meta[num].name, syscalls_meta[num].idx++);
            else
                fprintf(py, "idc.MakeName(0x%08x, 'syscall_%02x_%d')\n", addr+4*i,
                    num, syscalls_meta[num].idx++);

            buf[i] = be32(num | 0xEF800000);
        }
    }
}

static int find_phdrs()
{
    u32 i;
    for(i=0; i<hdr.e_phnum; i++)
    {
        if(fseek(fd, hdr.e_phoff + i*hdr.e_phentsize, SEEK_SET) != 0)
        {
            perror("fseek");
            return 1;
        }

        Elf32_Phdr phdr;

        if(fread(&phdr, sizeof(phdr), 1, fd) != 1)
        {
            perror("fread3");
            return 1;
        }

        phdr.p_vaddr  = be32(phdr.p_vaddr);
        phdr.p_memsz  = be32(phdr.p_memsz);
        phdr.p_offset = be32(phdr.p_offset);
        phdr.p_filesz = be32(phdr.p_filesz);
        phdr.p_flags  = be32(phdr.p_flags);

        printf("---\n");
        printf("Vaddr %08x\n", phdr.p_vaddr);
        printf("Pid %08x\n", phdr.p_flags>>20);
        printf("---\n");
        /* Look for the PT_LOAD header. */
        if(be32(phdr.p_type) == PT_LOAD)
        {
            /* Does this segment belong to our process? TODO: Improve! */
            if(((phdr.p_flags >> 20) & 0xFF) == pid)
            {
                printf("Program header:\n");
                printf("  Addr:  %08x\n", phdr.p_vaddr);
                printf("  Size:  %08x\n", phdr.p_memsz);
                printf("  Flags: %s%s%s\n", phdr.p_flags&4 ? "r":"",
                       phdr.p_flags&2 ? "w":"", phdr.p_flags&1 ? "x":"");

                u8* buf = malloc(phdr.p_memsz);

                if(buf == NULL)
                {
                    perror("malloc");
                    return 1;
                }

                memset(buf, 0, phdr.p_memsz);

                if(phdr.p_memsz < phdr.p_filesz)
                {
                    printf("Bad ELF: data is bigger than memory area..\n");
                    free(buf);
                    return 1;
                }

                if(fseek(fd, phdr.p_offset, SEEK_SET) != 0)
                {
                    perror("fseek");
                    free(buf);
                    return 1;
                }

                if(phdr.p_filesz)
                {
                    if(fread(buf, phdr.p_filesz, 1, fd) != 1)
                    {
                        perror("fread4");
                        free(buf);
                        return 1;
                    }
                }

                if(num_segments == MAX_SEGMENTS)
                {
                    printf("Too many segments found..\n");
                    free(buf);
                    return 1;
                }

                if(phdr.p_flags & PF_X)
                    fix_und_instructions((u32*)buf, phdr.p_memsz, phdr.p_vaddr);

                segments[num_segments].vaddr  = phdr.p_vaddr;
                segments[num_segments].size   = phdr.p_memsz;
                segments[num_segments].buffer = buf;
                segments[num_segments].flags  = phdr.p_flags;

                num_segments++;
            }
        }
    }

    return 0;
}

static int output_hdr()
{
    Elf32_Ehdr hdr_out;
    memset(&hdr_out, 0, sizeof(hdr_out));

    hdr_out.e_ident[EI_MAG0]       = ELFMAG0;
    hdr_out.e_ident[EI_MAG1]       = ELFMAG1;
    hdr_out.e_ident[EI_MAG2]       = ELFMAG2;
    hdr_out.e_ident[EI_MAG3]       = ELFMAG3;
    hdr_out.e_ident[EI_CLASS]      = ELFCLASS32;
    hdr_out.e_ident[EI_DATA]       = ELFDATA2MSB;
    hdr_out.e_ident[EI_VERSION]    = EV_CURRENT;
    hdr_out.e_ident[EI_OSABI]      = ELFOSABI_ARM;
    hdr_out.e_ident[EI_ABIVERSION] = 1;

    hdr_out.e_type      = be32(ET_EXEC);
    hdr_out.e_machine   = be16(EM_ARM);
    hdr_out.e_version   = be32(EV_CURRENT);
    hdr_out.e_entry     = be32(entry);
    hdr_out.e_phoff     = be32(sizeof(hdr_out));
    hdr_out.e_shoff     = 0;
    hdr_out.e_flags     = 0;
    hdr_out.e_ehsize    = be16(sizeof(Elf32_Ehdr));
    hdr_out.e_phentsize = be16(sizeof(Elf32_Phdr));
    hdr_out.e_phnum     = be16(num_segments);
    hdr_out.e_shentsize = be16(sizeof(Elf32_Shdr));
    hdr_out.e_shnum     = 0;
    hdr_out.e_shstrndx  = be16(SHN_UNDEF);

    if(fwrite(&hdr_out, sizeof(hdr_out), 1, out) != 1)
    {
        perror("fwrite");
        return 1;
    }

    return 0;
}

static int output_phdrs()
{
    u32 phdr_data_offset = sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr)*num_segments;
    u32 i;

    for(i=0; i<num_segments; i++)
    {
        Elf32_Phdr phdr_out;
        memset(&phdr_out, 0, sizeof(phdr_out));

        phdr_out.p_type   = be32(PT_LOAD);
        phdr_out.p_offset = be32(phdr_data_offset);
        phdr_out.p_vaddr  = be32(segments[i].vaddr);
        phdr_out.p_paddr  = be32(segments[i].vaddr);
        phdr_out.p_filesz = be32(segments[i].size);
        phdr_out.p_memsz  = be32(segments[i].size);
        phdr_out.p_flags  = be32(segments[i].flags);
        phdr_out.p_align  = be32(1);

        if(fwrite(&phdr_out, sizeof(phdr_out), 1, out) != 1)
        {
            perror("fwrite");
            return 1;
        }

        phdr_data_offset += segments[i].size;
    }

    return 0;
}

int main(int argc, char* argv[])
{
    char path[256];
    char* elf;

    if(argc == 3)
    {
        elf = argv[1];
        pid = atoi(argv[2]);
    }
    else
    {
        if(argc == 4 && !strcmp(argv[1], "--dump-segs"))
        {
            elf = argv[2];
            pid = atoi(argv[3]);
            dump_segments = 1;
        }
        else
        {
            printf("%s [--dump-segs] <in.elf> <pid>\n", argv[0]);
            return 1;
        }
    }

    fd = fopen(elf, "rb");

    if(fd == NULL)
    {
        perror("fopen");
        return 1;
    }

    if(fread(&hdr, sizeof(hdr), 1, fd) != 1)
    {
        perror("fread5");
        fclose(fd);
        return 1;
    }

    if(!check_elf_header())
    {
        printf("Bad ELF magic..\n");
        fclose(fd);
        return 1;
    }

    hdr.e_phoff     = be32(hdr.e_phoff);
    hdr.e_phentsize = be16(hdr.e_phentsize);
    hdr.e_phnum     = be16(hdr.e_phnum);

    if(find_aux_info())
    {
        fclose(fd);
        return 1;
    }

    snprintf(path, sizeof(path), "%s.%d.py", elf, pid);
    py = fopen(path, "w");

    fprintf(py, "import idc\n");

    if(find_phdrs())
    {
        fclose(fd);
        return 1;
    }

    snprintf(path, sizeof(path), "%s.%d.elf", elf, pid);
    out = fopen(path, "wb");

    if(out == NULL)
    {
        perror("fopen");
        fclose(fd);
        return 1;
    }

    if(output_hdr())
    {
        fclose(fd);
        fclose(out);
        return 1;
    }

    if(output_phdrs())
    {
        fclose(fd);
        fclose(out);
        return 1;
    }

    /* Output memory contents. */
    u32 i;
    for(i=0; i<num_segments; i++)
    {
        if(fwrite(segments[i].buffer, segments[i].size, 1, out) != 1)
        {
            perror("fwrite");
            fclose(fd);
            fclose(out);
            return 1;
        }

        if(dump_segments)
        {
            char buf[256];
            snprintf(buf, sizeof buf, "%d_%08x.bin", pid, segments[i].vaddr);
            FILE* fd_seg = fopen(buf, "wb");
            fwrite(segments[i].buffer, segments[i].size, 1, fd_seg);
            fclose(fd_seg);
        }
    }

    fclose(fd);
    fclose(out);
    return 0;
}
