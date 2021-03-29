section .text
global my_execve

my_execve:
    lea rsp,[stk]       ;;如下所述，防止内存访问异常
    call to32           ;;转换为32位
    mov eax,11          ;;32位的sys_execve 64位的sys_munmap
    mov ebx,edi         ;;32位和64位参数所用寄存器不同需要手动修改
    mov ecx,esi
    mov edx,edx
    int 0x80            ;;32位不能使用syscall，只能使用此指令
    ret
to32:
    mov DWORD [rsp+4],0x23
    retf

section .bss            ;;这里创建了一个栈，因为to32后rsp只有低位也就是esp有效了，若不这样做它将会指向一个不可访问的区域，这将会导致访问异常
    resb 1000           ;;在实际利用过程中找到一个可访问的低位地址就好了
stk:
