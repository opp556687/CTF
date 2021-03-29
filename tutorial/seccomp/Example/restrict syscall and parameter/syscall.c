#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>

int main(void)
{
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write),1,SCMP_A2(SCMP_CMP_EQ,0x10));//第2(从0)个参数等于0x10
	seccomp_load(ctx);
	write(1,"i will give you a shell\n",24);//不被拦截
	write(1,"1234567812345678",0x10);//被拦截
	return 0;
}
