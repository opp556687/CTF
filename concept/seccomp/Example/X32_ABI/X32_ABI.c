#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

void sandbox(){
    unsigned char bpf[] = {32,0,0,0,4,0,0,0,21,0,0,7,62,0,0,192,32,0,0,0,0,0,0,0,21,0,5,0,2,0,0,0,21,0,4,0,9,0,0,0,21,0,3,0,101,0,0,0,21,0,2,0,1,1,0,0,21,0,1,0,48,1,0,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0};
	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	struct sock_fprog sfp = {10,bpf}; //10代表沙箱规则条数
	prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&sfp);
}

int main(){
	char * shellcode;
	void (*vul)();
	puts("sandbox init");

	write(1,"shellcode:",0x10);
	shellcode = mmap(0,0x1000,PROT_EXEC | PROT_READ |PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,0,0);
	read(0,shellcode,0x1000);
	printf("call %p",shellcode);
	vul = shellcode;
	sandbox();
	vul();
	//shellcode();
}
