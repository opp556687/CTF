---
tags: 2020 程式安全
---
# HW8
## wishMachine
### 題目分析
* 這個binary是static link而且被strip過的  
![](https://i.imgur.com/fb8245B.png)
* 因為被strip過所以所有的函數名都沒有了
* 直接打開ida來看會直接定位到start的地方這邊start呼叫的function是__libc_start_main  
![](https://i.imgur.com/fc3WnMY.png)
* 從_libc_start_main的原形可以知道他擺放的第一個參數是main的位置所以就知道sub_4014F0是main的位置
```c=
int __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));
```
* 進到main會看到這邊某些事會做999次然後會輸出flag為多少  
![](https://i.imgur.com/4Zb3JxT.png)
* 再來右半邊loc_400D4E從那很長的字串可以知道是printf後面接著memset把70個byte都清成0之後會讀取輸入而且有個%70s因此可以知道是scanf這樣就可以把已知的函數重新命名  
![](https://i.imgur.com/3Sa2Fjh.png)
* 再來進去看sub_400E0A他會把我們的輸入字串放進這裡面
* 這邊直接看decompile後的結果會看到他在裡面做一些取值得動作分別把值放到全域變數上而傳進來的字串的指標就被放到qword_8A2108上面這邊會一直做到i的值大於dword_8A2118  
![](https://i.imgur.com/vT4PqkU.png)
* 最後會把qword_8A2100轉型成函數指針把它當作函式來呼叫計算一下迴圈執行第一次的結果可以知道qword_8A2100的值是0x4011D6因為他被當作函式來呼叫所以會進到0x4011D6裡面
* 這邊可以看到sub_0x4011D6他會從input + dword_8A2114 + i取一個字元用他的ascii來當作迴圈執行的次數來算斐波那契数列最後看算出來的值跟input+i\*4+5\*4那個位置dword的值是不是一樣的如果不一樣就執行sub_40F130進去看sub_40F130會發現它是exit所以如果比較不相等就會直接執行exit  
![](https://i.imgur.com/uFFJb0l.png)
* 而這邊只要i的值大於等於dword_8A2118就會結束檢查回到上一層剛剛在給全域變數值那邊
* 所以這邊再回去看知道sub_400E0A就知道他這邊給每個全域變數值得意義了
    * dword_8A2114是代表序號的第幾個字
    * dword_8A2118是代表檢查的時候迴圈要跑幾次
    * dword_8A211C是第一次檢查的值因為input的位置是0x8A2108所以在檢查的function裡面當i=0時0x8A2108+5\*4=0x8a211c
    * dword_8A2120是第二次檢查的值進到檢查的function當i=1時就會檢查0x8A2108+1\*45\*4=0x8a2120就是這個的值
    * dword_8A2110和qword_8A2100是組成function pointer的值
* 所以知道他會去執行qword_8A2100值所代表的那個位置的函式來檢查輸入的序號是不是正確的如果不正確就會exit去算一下他的值會發現他總共有五個結果
    * 0x400FBE這邊是把某個字元拿來乘上135看結果是不是跟檢查的值一樣  
    ![](https://i.imgur.com/h76YIxo.png)
    * 0x40102D這邊是拿某個字元的ascii當作迴圈的次數算一個值然後看是不是跟要檢查的值一樣  
    ![](https://i.imgur.com/pdW0wnu.png)
    * 0x4010C8這邊是看檢查的值跟某個字元xor 0x52756279的結果是不是一樣  
    ![](https://i.imgur.com/Xwd0k9b.png)
    * 0x401138這邊一樣是透過迴圈來做運算跟檢查值做比較  
    ![](https://i.imgur.com/73wgJgz.png)
    * 0x4011D6這邊就是最一開始看到的算斐波那契数列的地方  
    ![](https://i.imgur.com/HmB85up.png)
* 這邊一組序號通過所有的檢查之後就會再回到main去執行sub_400F69做解密  
![](https://i.imgur.com/60jGU9l.png)
* 然後再輸入下一組的序號總共會做1000次結束之後就會輸出flag
* 既然已經知道他所有檢查的規則就可以寫個腳本直接來把1000組序號都爆出來最後再餵進去就會拿到flag了
### Exploit
* 分別寫出五個檢查序號的function然後按照檢查的規則去產生序號
* 產生完1000個序號之後就用pwntools來送最後就能拿到flag
```python=
import ctypes
from pwn import *

array = [...略...]

def fun_0x400FBE():
    fun_i = 0
    while 1:
        if fun_i >= dword_8A2118:
            break
        if fun_i == 0:
            input[dword_8A2114+fun_i] = chr(dword_8A211C//135)
        elif fun_i == 1:
            input[dword_8A2114+fun_i] = chr(dword_8A2120//135)
        else:
            print("something wrong in fun_0x400FBE")
            exit(0)
        fun_i+=1

def fun_0x40102D():
    fun_i = 0
    v1 = 0
    while 1:
        if fun_i >= dword_8A2118:
            break
        else:
            if fun_i == 0:
                v1 = dword_8A211C
            elif fun_i == 1:
                v1 = dword_8A2120
            else:
                print("wrong in fun_0x40102D")
                exit(0)
            sum = 0
            j = 0
            while sum != v1:
                if (j&1) != 0:
                    sum += 2
                else:
                    sum += 11
                j+=1
            input[dword_8A2114 + fun_i] = chr(j)
        fun_i+=1

def fun_0x4010C8():
    fun_i = 0
    while 1:
        if fun_i >= dword_8A2118:
            break
        if fun_i == 0:
            input[dword_8A2114 + fun_i] = chr(dword_8A211C ^ 0x52756279)
        elif fun_i == 1:
            input[dword_8A2114 + fun_i] = chr(dword_8A2120 ^ 0x52756279)
        else:
            print("wrong in fun_0x4010C8")
            exit(0)
        fun_i+=1

def fun_0x401138():
    fun_i = 0
    v1 = -88035316
    while 1:
        if fun_i >= dword_8A2118:
            break
        else:
            if fun_i == 0:
                v1 = ctypes.c_int(dword_8A211C)
            elif fun_i == 1:
                v1 = ctypes.c_int(dword_8A2120)
            else:
                print("wrong in fun_0x401138")
                exit(0)
            sum = -88035316
            j = 0
            while sum != v1.value:
                if (j&1) != 0:
                    sum -= 120
                else:
                    sum -= 30600
                j+=1
            input[dword_8A2114 + fun_i] = chr(j)
        fun_i+=1

def fun_0x4011D6():
    fun_i = 0
    while 1:
        if fun_i >= dword_8A2118:
            break
        v3 = ctypes.c_uint(0)
        v4 = ctypes.c_uint(1)
        v1 = 0
        if fun_i == 0:
            v1 = dword_8A211C
        elif fun_i == 1:
            v1 = dword_8A2120
        else:
            print("wrong in fun_0x4011D6")
            exit(0)
        sum = ctypes.c_uint(0)
        j = 0
        while sum.value != v1:
            sum = ctypes.c_uint(v3.value + v4.value)
            v3 = v4
            v4 = sum
            j += 1
        input[dword_8A2114 + fun_i] = chr(j)
        fun_i+=1

num1 = 0
num2 = 0
num3 = 0
num4 = 0
num5 = 0
index = 0
input = ['a']*70
serial = []
i = 0
for _ in range(1000):
    temp = ''
    while 1:
        if i<=69:
            dword_8A2114 = int.from_bytes(bytes([array[0+index*40+20]])+bytes([array[1+index*40+20]])+bytes([array[2+index*40+20]])+bytes([array[3+index*40+20]]), 'little')
            dword_8A2118 = int.from_bytes(bytes([array[0+index*40+24]])+bytes([array[1+index*40+24]])+bytes([array[2+index*40+24]])+bytes([array[3+index*40+24]]), 'little')
            dword_8A211C = int.from_bytes(bytes([array[0+index*40+28]])+bytes([array[1+index*40+28]])+bytes([array[2+index*40+28]])+bytes([array[3+index*40+28]]), 'little')
            dword_8A2120 = int.from_bytes(bytes([array[0+index*40+32]])+bytes([array[1+index*40+32]])+bytes([array[2+index*40+32]])+bytes([array[3+index*40+32]]), 'little')
            dword_8A2110 = int.from_bytes(bytes([array[0+index*40+16]])+bytes([array[1+index*40+16]])+bytes([array[2+index*40+16]])+bytes([array[3+index*40+16]]), 'little')
            fun_ptr = int.from_bytes(bytes([array[0+index*40]])+bytes([array[1+index*40]])+bytes([array[2+index*40]])+bytes([array[3+index*40]]), 'little') + dword_8A2110
            index+=1
            i+=dword_8A2118

            if fun_ptr == 0x400FBE:
                fun_0x400FBE()
            elif fun_ptr == 0x40102D:
                fun_0x40102D()
            elif fun_ptr == 0x4010C8:
                fun_0x4010C8()
            elif fun_ptr == 0x401138:
                fun_0x401138()
            elif fun_ptr == 0x4011D6:
                fun_0x4011D6()
            else:
                print("wrong in fun_ptr")
                print(hex(fun_ptr))
                exit(0)
        else:
            for gg in input:
                temp += gg
            serial.append(temp)
            i=0
            break

p = process('./wishMachine')
p.recvuntil('number\n')
for i in range(1000):
    p.sendline(serial[i])
p.interactive()
```
>FLAG\{7hes3_func710n_ptrs_g1v3_m3_l0t_0o0of_f4n_I_w4n7_m00r3_11!!l1!|!}
## Curse
## SecureContainProtect
### 題目分析
* 這題直接打開ida decompile回去在main會看到一些上下左右和移動跟輸入之類的操作還有按q會結束按z會執行finish  
![](https://i.imgur.com/Zplu2LA.png)
* 因為其他部分不是很重要所以直接看finish就好也就是sub_F38()
* 裡面沒有很多東西只有把輸入的數獨分別拿來跟兩個陣列byte_2020E0和byte_202D40做xor然後算和如果算出來的和和要求的一樣就繼續進行下一步不然就輸出wrong然後exit
![](https://i.imgur.com/6xILuMI.png)
* 當前面算出來的和跟要求的一樣就會要求使用者輸入action code
* 之後再拿輸入的action code跟數獨的值還有byte_202E00這個陣列裡面的值做xor然後再算和如果相同就會輸出xor之後的結果就是flag不然就exit
### Exploit
* 已經知道題目的要求有兩個第一個是數獨的結果要是對的還有就是輸入的action code也要是對的才能通過xor的運算來拿到flag
* 一開始先算出數獨的結果
* 如果只輸出原本就有值得部分沒有值就輸出空白就會得到一些圖案而且都是`â`
![](https://i.imgur.com/qbNoLnD.png)
```python=
for i in range(len(unknow3161)):
    unknow3161[i] ^= sudoku[i%81]
    if sudoku[i%81] != 0:
        print(chr(unknow3161[i]), end='')
    else:
        print(' ', end='')
```
* 然後測試之後會發現如果在格子內填入錯誤的值會輸出`â`以外的符號所以就一個一個測試就可以把整個數獨的結果解出來
* 解出來之後就通過第一階段就剩下輸入action code的部分
* 因為已經知道結果是ascii art而ascii art會有同樣的字連續一直出現的特性因為題目是拿一個陣列的內容跟數獨結果還有action code去做xor
* 計算的過程是result = array[i] ^ sudoku[i%81] ^ actionCode[i%len(actionCode)]因為xor是可逆的所以可以解設一個可是字元當作result然後去反推action code所以就變成actionCode[i%len(actionCode)] = result ^ array[i] ^ sudoku[i%81]
```python=
for ascii in range(32, 127):
    for i in range(len(unknow6015)):
        key = sudoku[i%81] ^ ascii ^ unknow6015[i]
        print(chr(key), end='')
```
* 測試之後發現當ascii為32也就是空白的時候會輸出action code雖然出來的結果並不一定是完整的action code但是前後湊一湊就能湊出完整的action code是`decrypt_the_document_of_SCP-2521`  
![](https://i.imgur.com/s6meG6F.png)
* 既然有action code 數獨的結果 還有題目給定的陣列就可以去做xor來解密還原出原本的內容了
```python=
unknow6015 = [...略...]

sudoku = [
    0x08,0x01,0x02,0x07,0x05,0x03,0x06,0x04,0x09,
    0x09,0x04,0x03,0x06,0x08,0x02,0x01,0x07,0x05,
    0x06,0x07,0x05,0x04,0x09,0x01,0x02,0x08,0x03,
    0x01,0x05,0x04,0x02,0x03,0x07,0x08,0x09,0x06,
    0x03,0x06,0x09,0x08,0x04,0x05,0x07,0x02,0x01,
    0x02,0x08,0x07,0x01,0x06,0x09,0x05,0x03,0x04,
    0x05,0x02,0x01,0x09,0x07,0x04,0x03,0x06,0x08,
    0x04,0x03,0x08,0x05,0x02,0x06,0x09,0x01,0x07,
    0x07,0x09,0x06,0x03,0x01,0x08,0x04,0x05,0x02]

key = 'decrypt_the_document_of_SCP-2521'
for i in range(len(unknow6015)):
    unknow6015[i] = unknow6015[i] ^ ord(key[i%len(key)]) ^ sudoku[i%81]
    print(chr(unknow6015[i]), end='')
```
* 還原出來的結果是ascii art因為有很多空白所以在推action code的時候空白會還原出action code
![](https://i.imgur.com/26mdhrP.png)
>FLAG{oh_my_g0d_hoo0ow_did_you_decrypt_this???}