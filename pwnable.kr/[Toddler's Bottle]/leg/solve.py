key1 = 0x8ce4   # 0x00008cdc <+8>:  mov	r3, pc -> pc = current address+8
key2 = 0x8d0c   # 0x00008d00 <+16>: bx	r6 -> if pc lowest byte = 1 transfer to thumb (pc = current address+4)
                # so 0x00008d04 <+20>: mov	r3, pc -> pc = current address + 4
key3 = 0x8d80   # 0x00008d28 <+8>:  mov	r3, lr -> lr is used to store return address

key = key1 + key2 + key3
print(key)
