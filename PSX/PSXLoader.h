//
//  PSXLoader.h
//  PSX
//
//  Created by Makigumo on 2016/12/11.
//    Copyright © 2016年 Makigumo. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Hopper/Hopper.h>

#ifdef __linux__

@interface NSData (NSData)

- (NSRange)rangeOfData:(NSData *)aData
               options:(NSUInteger)mask
                 range:(NSRange)aRange;

@end

#endif

const char *const HEADER_MAGIC_PSX = "PS-X EXE";
const char *const HEADER_MAGIC_SCE = "SCE EXE";

typedef struct PSX_HEADER_PSX {
    char id[8];
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t pc0;
    uint32_t reserved3;
    uint32_t t_addr;
    uint32_t t_size;
    uint32_t reserved4;
    uint32_t reserved5;
    uint32_t reserved6;
    uint32_t reserved7;
    uint32_t s_addr;
    uint32_t s_size;
    uint32_t SavedSP;
    uint32_t SavedFP;
    uint32_t SavedGP;
    uint32_t SavedRA;
    uint32_t SavedS0;
} PsxHeader_PSX;

typedef struct PSX_HEADER_SCE {
    char id[8];
    uint32_t text;
    uint32_t data;
    uint32_t pc0;
    uint32_t gp0;
    uint32_t t_addr;
    uint32_t t_size;
    uint32_t d_addr;
    uint32_t d_size;
    uint32_t b_addr;
    uint32_t b_size;
    uint32_t s_addr;
    uint32_t s_size;
    uint32_t SavedSP;
    uint32_t SavedFP;
    uint32_t SavedGP;
    uint32_t SavedRA;
    uint32_t SavedS0;
} PsxHeader_SCE;

typedef struct {
    union {
        PsxHeader_PSX psx;
        PsxHeader_SCE sce;
    };
} PsxHeader;

typedef struct bioscall {
    const uint8_t adr;
    const uint8_t val;
    const char *const name;
} BIOS_CALL;

// source: http://problemkaputt.de/psx-spx.htm#biosfunctionsummary
const struct bioscall bios_calls[] = {
        {0xa0, 0x00, "open"},
        {0xa0, 0x01, "lseek"},
        {0xa0, 0x02, "read"},
        {0xa0, 0x03, "write"},
        {0xa0, 0x04, "close"},
        {0xa0, 0x05, "ioctl"},
        {0xa0, 0x06, "exit"},
        {0xa0, 0x07, "sys_b0_39"},
        {0xa0, 0x08, "getc"},
        {0xa0, 0x09, "putc"},
        {0xa0, 0x0a, "todigit"},
        {0xa0, 0x0b, "atof"},
        {0xa0, 0x0c, "strtoul"},
        {0xa0, 0x0d, "strtol"},
        {0xa0, 0x0e, "abs"},
        {0xa0, 0x0f, "labs"},
        {0xa0, 0x10, "atoi"},
        {0xa0, 0x11, "atol"},
        {0xa0, 0x12, "atob"},
        {0xa0, 0x13, "setjmp"},
        {0xa0, 0x14, "longjmp"},
        {0xa0, 0x15, "strcat"},
        {0xa0, 0x16, "stncat"},
        {0xa0, 0x17, "strcmp"},
        {0xa0, 0x18, "strncmp"},
        {0xa0, 0x19, "strcpy"},
        {0xa0, 0x1a, "strncpy"},
        {0xa0, 0x1b, "strlen"},
        {0xa0, 0x1c, "index"},
        {0xa0, 0x1d, "rindex"},
        {0xa0, 0x1e, "strchr"},
        {0xa0, 0x1f, "strrchr"},
        {0xa0, 0x20, "strpbrk"},
        {0xa0, 0x21, "strspn"},
        {0xa0, 0x22, "strcspn"},
        {0xa0, 0x23, "strtok"},
        {0xa0, 0x24, "strstr"},
        {0xa0, 0x25, "toupper"},
        {0xa0, 0x26, "tolower"},
        {0xa0, 0x27, "bcopy"},
        {0xa0, 0x28, "bzero"},
        {0xa0, 0x29, "bcmp"},
        {0xa0, 0x2a, "memcpy"},
        {0xa0, 0x2b, "memset"},
        {0xa0, 0x2c, "memmove"},
        {0xa0, 0x2d, "memcmp"},
        {0xa0, 0x2e, "memchr"},
        {0xa0, 0x2f, "rand"},
        {0xa0, 0x30, "srand"},
        {0xa0, 0x31, "qsort"},
        {0xa0, 0x32, "strtod"},
        {0xa0, 0x33, "malloc"},
        {0xa0, 0x34, "free"},
        {0xa0, 0x35, "lsearch"},
        {0xa0, 0x36, "bsearch"},
        {0xa0, 0x37, "calloc"},
        {0xa0, 0x38, "realloc"},
        {0xa0, 0x39, "InitHeap"},
        {0xa0, 0x3a, "_exit"},
        {0xa0, 0x3b, "getchar"},
        {0xa0, 0x3c, "putchar"},
        {0xa0, 0x3d, "gets"},
        {0xa0, 0x3e, "puts"},
        {0xa0, 0x3f, "printf"},
        {0xa0, 0x40, "SystemErrorUnresolvedException"},
        {0xa0, 0x41, "LoadExeHeader"},
        {0xa0, 0x42, "LoadExeFile"},
        {0xa0, 0x43, "DoExecute"},
        {0xa0, 0x44, "FlushCache"},
        {0xa0, 0x45, "init_a0_b0_c0_vectors"},
        {0xa0, 0x46, "GPU_dw"},
        {0xa0, 0x47, "gpu_send_dma"},
        {0xa0, 0x48, "SendGP1Command"},
        {0xa0, 0x49, "GPU_cw"},
        {0xa0, 0x4a, "GPU_cwb"},
        {0xa0, 0x4b, "send_gpu_linked_list"},
        {0xa0, 0x4c, "gpu_abort_dma"},
        {0xa0, 0x4d, "GetGPUStatus"},
        {0xa0, 0x4e, "gpu_sync"},
        {0xa0, 0x4f, "SystemError"},
        {0xa0, 0x50, "SystemError"},
        {0xa0, 0x51, "LoadExec"},
        {0xa0, 0x52, "GetSysSp"},
        {0xa0, 0x53, "SystemError"},
        {0xa0, 0x54, "CdInit"},
        {0xa0, 0x55, "_bu_init"},
        {0xa0, 0x56, "CdRemove"},
        {0xa0, 0x57, "return0_1"},
        {0xa0, 0x58, "return0_2"},
        {0xa0, 0x59, "return0_3"},
        {0xa0, 0x5a, "return0_4"},
        {0xa0, 0x5b, "dev_tty_init"},
        {0xa0, 0x5c, "dev_tty_open"},
        {0xa0, 0x5d, "dev_tty_in_out"},
        {0xa0, 0x5e, "dev_tty_ioctl"},
        {0xa0, 0x5f, "dev_cd_open"},
        {0xa0, 0x60, "dev_cd_read"},
        {0xa0, 0x61, "dev_cd_close"},
        {0xa0, 0x62, "dev_cd_firstfile"},
        {0xa0, 0x63, "dev_cd_nextfile"},
        {0xa0, 0x64, "dev_cd_chdir"},
        {0xa0, 0x65, "dev_card_open"},
        {0xa0, 0x66, "dev_card_read"},
        {0xa0, 0x67, "dev_card_write"},
        {0xa0, 0x68, "dev_card_close"},
        {0xa0, 0x69, "dev_card_firstfile"},
        {0xa0, 0x6a, "dev_card_nextfile"},
        {0xa0, 0x6b, "dev_card_erase"},
        {0xa0, 0x6c, "dev_card_undelete"},
        {0xa0, 0x6d, "dev_card_format"},
        {0xa0, 0x6e, "dev_card_rename"},
        //{0xa0, 0x6f, ""},
        {0xa0, 0x70, "_bu_init"},
        {0xa0, 0x71, "CdInit"},
        {0xa0, 0x72, "CdRemove"},
        //{0xa0, 0x73, ""},
        //{0xa0, 0x74, ""},
        //{0xa0, 0x75, ""},
        //{0xa0, 0x76, ""},
        //{0xa0, 0x77, ""},
        {0xa0, 0x78, "CdAsyncSeekL"},
        //{0xa0, 0x79, ""},
        //{0xa0, 0x7a, ""},
        //{0xa0, 0x7b, ""},
        {0xa0, 0x7c, "CdAsyncGetStatus"},
        //{0xa0, 0x7d, ""},
        {0xa0, 0x7e, "CdAsyncReadSector"},
        //{0xa0, 0x7f, ""},
        //{0xa0, 0x80, ""},
        {0xa0, 0x81, "CdAsyncSetMode"},
        //{0xa0, 0x82, ""},
        //{0xa0, 0x83, ""},
        //{0xa0, 0x84, ""},
        {0xa0, 0x85, "CdStop"},
        //{0xa0, 0x86, ""},
        //{0xa0, 0x87, ""},
        //{0xa0, 0x88, ""},
        //{0xa0, 0x89, ""},
        //{0xa0, 0x8a, ""},
        //{0xa0, 0x8b, ""},
        //{0xa0, 0x8c, ""},
        //{0xa0, 0x8d, ""},
        //{0xa0, 0x8e, ""},
        //{0xa0, 0x8f, ""},
        {0xa0, 0x90, "CdromIoIrqFunc1"},
        {0xa0, 0x91, "CdromDmaIrqFunc1"},
        {0xa0, 0x92, "CdromIoIrqFunc2"},
        {0xa0, 0x93, "CdromDmaIrqFunc2"},
        {0xa0, 0x94, "CdromGetInt5errCode"},
        {0xa0, 0x95, "CdInitSubFunc"},
        {0xa0, 0x96, "AddCDROMDevice"},
        {0xa0, 0x97, "AddMemCardDevice"},
        {0xa0, 0x98, "DisableKernelIORedirection"},
        {0xa0, 0x99, "EnableKernelIORedirection"},
        //{0xa0, 0x9a, ""},
        //{0xa0, 0x9b, ""},
        {0xa0, 0x9c, "SetConf"},
        {0xa0, 0x9d, "GetConf"},
        {0xa0, 0x9e, "SetCdromIrqAutoAbort"},
        {0xa0, 0x9f, "SetMemSize"},
        {0xa0, 0xa0, "WarmBoot"},
        {0xa0, 0xa1, "SystemErrorBootOrDiskFailure"},
        {0xa0, 0xa2, "EnqueueCdIntr"},
        {0xa0, 0xa3, "DequeueCdIntr"},
        {0xa0, 0xa4, "CdGetLbn"},
        {0xa0, 0xa5, "CdReadSector"},
        {0xa0, 0xa6, "CdGetStatus"},
        {0xa0, 0xa7, "bu_callback_okay"},
        {0xa0, 0xa8, "bu_callback_err_write"},
        {0xa0, 0xa9, "bu_callback_err_busy"},
        {0xa0, 0xaa, "bu_callback_err_eject"},
        {0xa0, 0xab, "_card_info"},
        {0xa0, 0xac, "_card_load"},
        {0xa0, 0xad, "set_card_auto_format"},
        {0xa0, 0xae, "bu_callback_err_prev_write"},
        {0xa0, 0xaf, "card_write_test"},
        //{0xa0, 0xb0, ""},
        //{0xa0, 0xb1, ""},
        {0xa0, 0xb2, "ioabort_raw"},
        //{0xa0, 0xb3, ""},
        {0xa0, 0xb4, "GetSystemInfo"},


        {0xb0, 0x00, "alloc_kernel_memory"},
        {0xb0, 0x01, "free_kernel_memory"},
        {0xb0, 0x02, "init_timer"},
        {0xb0, 0x03, "get_timer"},
        {0xb0, 0x04, "enable_timer_irq"},
        {0xb0, 0x05, "disable_timer_irq"},
        {0xb0, 0x06, "restart_timer"},
        {0xb0, 0x07, "DeliverEvent"},
        {0xb0, 0x08, "OpenEvent"},
        {0xb0, 0x09, "CloseEvent"},
        {0xb0, 0x0a, "WaitEvent"},
        {0xb0, 0x0b, "TestEvent"},
        {0xb0, 0x0c, "EnableEvent"},
        {0xb0, 0x0d, "DisableEvent"},
        {0xb0, 0x0e, "OpenThread"},
        {0xb0, 0x0f, "CloseThread"},
        {0xb0, 0x10, "ChangeThread"},
        //{0xb0, 0x11, ""},
        {0xb0, 0x12, "InitPad"},
        {0xb0, 0x13, "StartPad"},
        {0xb0, 0x14, "StopPad"},
        {0xb0, 0x15, "OutdatedPadInitAndStart"},
        {0xb0, 0x16, "OutdatedPadGetButtons"},
        {0xb0, 0x17, "ReturnFromException"},
        {0xb0, 0x18, "SetDefaultExitFromException"},
        {0xb0, 0x19, "SetCustomExitFromException"},
        //{0xb0, 0x1a, ""},
        //{0xb0, 0x1b, ""},
        //{0xb0, 0x1c, ""},
        //{0xb0, 0x1d, ""},
        //{0xb0, 0x1e, ""},
        //{0xb0, 0x1f, ""},
        {0xb0, 0x20, "UnDeliverEvent"},
        //
        //{0xb0, 0x30, ""},
        //{0xb0, 0x31, ""},
        {0xb0, 0x32, "open"},
        {0xb0, 0x33, "lseek"},
        {0xb0, 0x34, "read"},
        {0xb0, 0x35, "write"},
        {0xb0, 0x36, "close"},
        {0xb0, 0x37, "ioctl"},
        {0xb0, 0x38, "exit"},
        //{0xb0, 0x39, ""},
        {0xb0, 0x3a, "get"},
        {0xb0, 0x3b, "putc"},
        {0xb0, 0x3c, "getchar"},
        {0xb0, 0x3d, "putchar"},
        {0xb0, 0x3e, "gets"},
        {0xb0, 0x3f, "puts"},
        {0xb0, 0x40, "cd"},
        {0xb0, 0x41, "FormatDevice"},
        {0xb0, 0x42, "firstfile"},
        {0xb0, 0x43, "nextfile"},
        {0xb0, 0x44, "FileRename"},
        {0xb0, 0x45, "FileDelete"},
        {0xb0, 0x46, "FileUndelete"},
        {0xb0, 0x47, "AddDevice"},
        {0xb0, 0x48, "RemoveDevice"},
        {0xb0, 0x49, "PrintInstalledDevices"},
        {0xb0, 0x4a, "InitCard"},
        {0xb0, 0x4b, "StartCard"},
        {0xb0, 0x4c, "StopCard"},
        {0xb0, 0x4d, "_card_info_subfunc"},
        {0xb0, 0x4e, "write_card_sector"},
        {0xb0, 0x4f, "read_card_sector"},
        {0xb0, 0x50, "allow_new_card"},
        {0xb0, 0x51, "Krom2RawAdd"},
        //{0xb0, 0x52, ""},
        {0xb0, 0x53, "Krom2Offset"},
        {0xb0, 0x54, "GetLastError"},
        {0xb0, 0x55, "GetLastFileError"},
        {0xb0, 0x56, "GetC0Table"},
        {0xb0, 0x57, "GetB0Table"},
        {0xb0, 0x58, "get_bu_callback_port"},
        {0xb0, 0x59, "testdevice"},
        //{0xb0, 0x5a, ""},
        {0xb0, 0x5b, "ChangeClearPad"},
        {0xb0, 0x5c, "get_card_status"},
        {0xb0, 0x5d, "wait_card_status"},
        //{0xb0, 0x5e, ""},
        //{0xb0, 0x5f, ""},


        {0xc0, 0x00, "EnqueueTimerAndVblankIrqs"},
        {0xc0, 0x01, "EnqueueSyscallHandler"},
        {0xc0, 0x02, "SysEnqIntRP"},
        {0xc0, 0x03, "SysDeqIntRP"},
        {0xc0, 0x04, "get_free_EvCB_slot"},
        {0xc0, 0x05, "get_free_TCB_slot"},
        {0xc0, 0x06, "ExceptionHandler"},
        {0xc0, 0x07, "InstallExceptionHandlers"},
        {0xc0, 0x08, "SysInitMemory"},
        {0xc0, 0x09, "SysInitKMem"},
        {0xc0, 0x0a, "ChangeClearRCnt"},
        {0xc0, 0x0b, "SystemError"},
        {0xc0, 0x0c, "InitDefInt"},
        {0xc0, 0x0d, "SetIrqAutoAck"},
        //{0xc0, 0x0e, ""},
        //{0xc0, 0x0f, ""},
        //{0xc0, 0x10, ""},
        //{0xc0, 0x11, ""},
        {0xc0, 0x12, "InstallDevices"},
        {0xc0, 0x13, "FlushStdInOutPut"},
        {0xc0, 0x14, "return0_5"},
        {0xc0, 0x15, "tty_cdevinput"},
        {0xc0, 0x16, "tty_cdevscan"},
        {0xc0, 0x17, "tty_circgetc"},
        {0xc0, 0x18, "tty_circputc"},
        {0xc0, 0x19, "ioabort"},
        {0xc0, 0x1a, "set_card_find_mode"},
        {0xc0, 0x1b, "KernelRedirect"},
        {0xc0, 0x1c, "AdjustA0Table"},
        {0xc0, 0x1d, "get_card_find_mode"},
};

struct iomap_entry {
    const char *const name;
    const uint32_t address;
    const uint32_t length;
};

const struct iomap_entry iomap[] = {
        {"Expansion Region 1", 0x1F000000, 0x80000},
        {"Scratchpad", 0x1F800000, 0x400},
        {"Expansion 1 Base_Address", 0x1F801000, 0x4},
        {"Expansion 2 Base_Address", 0x1F801004, 0x4},
        {"Expansion 1 Delay_Size", 0x1F801008, 0x4},
        {"Expansion 3 Delay_Size", 0x1F80100c, 0x4},
        {"BIOS ROM", 0x1F801010, 0x4},
        {"SPU_DELAY", 0x1F801014, 0x4},
        {"CDROM_DELAY", 0x1F801018, 0x4},
        {"Expansion 2 Delay_Size", 0x1F80101c, 0x4},
        {"COM_DELAY/COMMON_DELAY", 0x1F801020, 0x4},

        {"JOY_DATA", 0x1F801040, 0x4},
        {"JOY_STAT", 0x1F801044, 0x4},
        {"JOY_MODE", 0x1F801048, 0x2},
        {"JOY_CTRL", 0x1F80104A, 0x2},
        {"JOY_BAUD", 0x1F80104E, 0x2},
        {"SIO_DATA", 0x1F801050, 0x4},
        {"SIO_STAT", 0x1F801054, 0x4},
        {"SIO_MODE", 0x1F801058, 0x2},
        {"SIO_CTRL", 0x1F80105A, 0x2},
        {"SIO_MISC", 0x1F80105C, 0x2},
        {"SIO_BAUD", 0x1F80105E, 0x2},

        {"RAM_SIZE", 0x1F801060, 0x4},

        {"I_STAT", 0x1F801070, 0x2},
        {"I_MASK", 0x1F801072, 0x2},

        {"DMA0 MDECin", 0x1F801080, 0xf},
        {"DMA1 MDECout", 0x1F801090, 0xf},
        {"DMA2 GPU", 0x1F8010A0, 0xf},
        {"DMA3 CDROM", 0x1F8010B0, 0xf},
        {"DMA4 SPU", 0x1F8010C0, 0xf},
        {"DMA5 SPIO", 0x1F8010D0, 0xf},
        {"DMA6 OTC", 0x1F8010E0, 0xf},
        {"DPCR", 0x1F8010F0, 0x4},
        {"DICR", 0x1F8010F4, 0x4},

        {"Timer 0 Dotclock", 0x1F801100, 0xf},
        {"Timer 1 Horizontal retrace", 0x1F801110, 0xf},
        {"Timer 2 1/8 system clock", 0x1F801120, 0xf},


};

@interface PSXLoader : NSObject <FileLoader>

@end
