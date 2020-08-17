#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stdlib.h>
#include <unistd.h>

extern void my_execve(char *,char**,char**);            //为了学习方便，将shellcode直接编入
char *args[]={
    "/bin/id",
//    "/bin/sh",
    0
};
int main()
{
    struct sock_filter filter[] = {
        //BPF_STMT(BPF_LD+BPF_W+BPF_ABS,4),             //这两步是检查arch的，先把注释掉，即不检查arch
        //BPF_JUMP(BPF_JMP+BPF_JEQ,0xc000003e,0,2),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),
        BPF_JUMP(BPF_JMP+BPF_JEQ,59,0,1),
        BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };
    prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
    prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);

    printf(":Beta~\n");
    my_execve(args[0],args,0);
    //execve("id",0,0);
    return 0;
}
