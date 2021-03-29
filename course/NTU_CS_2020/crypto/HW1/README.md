---
tags: 2020 程式安全
---
# HW1
## POA
### 題目分析
* 題目是一個AES加密的server是使用CBC的模式來加密會把flag拿去加密之後把IV和密文傳給連上的人接著server會讀取使用者輸入的內容拿前16個byte當作IV後面的內容當作密文去做解密解密之後不會顯示解密的結果只會顯示padding正確還是錯誤
* 因為AES加密是一個block一個block去做加密所以會把明文分段切成符合block長度最後一段如果不滿一個block的大小時會做padding把它補足一個block的長度
* 這題padding的方式為不足的部分第一個byte會補上\x80再來不足的補上\x00如果缺一個byte會在明文最後面補上\x80、不足兩個byte就補上\x80\x00、如果是不足三個byte就補上\x80\x00\x00以此類推
### 漏洞
* 因為IV可控加上知道他怎麼做padding然後還會顯示padding是否正確
* 所以可以利用oracle padding attack構造出能夠padding正確的payload來把明文一個byte一個byte爆搜出來
### Exploit
* CBC mode解密是密文跟先跟block解密之後再跟IV做xor就會得到明文
* 先假設密文跟block解密後得到的結果叫做p之後p跟IV做xor會得到明文所以
`p ^ IV = plain`
* 因為會顯示說padding是否正確所以可以暴力嘗試每個byte假設嘗試的byte是k
* 先從最後一個byte開始嘗試`p[15] ^ k = 0x80`這樣的話就會padding正確因為解出來是0x80他會認為是少1個byte ------ 1
* `p[15] ^ IV[15] = plain[15]`這是正常的解密得到的明文的最後一個byte ------ 2
* 從1結果可以得到`p[15] = k ^ 0x80`再代入2中就會變成`k ^ 0x80 ^ IV[15] = plain[15]`這樣當試到某個k會padding正確時就能得到這塊block明文的最後一個byte
* 再來以此類推`k ^ 0x80 ^ IV[14] = plain[14]`就可以得到倒數第二個byte
* 除了正在搜尋的那個byte要找到解出來是0x80以外其他已經搜尋過的要讓他解密出來結果是0x00這樣才不會padding錯誤
* 如果試到k和IV[i]是相同的時候要跳過不然他出來的結果會造成padding是正確但是結果不正確
* 因為k和IV[i]相同被跳過就會造成本來明文是0x80的部分被跳過就沒辦法產生明文是0x80的部分所以出現要送出時長度是31就知道上一輪的明文應該是0x80就去把結果補上0x80之後再繼續做就能把明文整個都爆搜出來
```python=
from pwn import *

r = remote('140.112.31.97', 30000)
# r = process(['python3', 'server.py'])

def oracle(message):
    r.sendlineafter('cipher = ', message.hex())
    if b'YESSSSSSSS' in r.recvline():
        return True
    else:
        return False

def xor(a, b):
    return bytes([x^y for x, y in zip(a, b)])

cipher = bytes.fromhex(r.recvline().strip().split(b' = ')[1].decode())
flag = b''
padlen = 15
for i in range(16, len(cipher), 16):
    iv, block = cipher[i-16:i], cipher[i: i+16]
    ans = b''
    for j in range(16):
        for k in range(256):
            if k == iv[16-1-j]:
                continue
            enc = iv[:16-1-j] + bytes([k]) + xor(iv[-j:], xor([0x00]*j, ans)) + block
            if len(enc) == 31:
                ans = bytes([iv[16-1-(j-1)] ^ iv[16-1-(j-1)] ^ 0x80]) + ans
                k = -1
                continue
            if oracle(enc):
                ans = bytes([iv[16-1-j] ^ k ^ 0x80]) + ans
                print(ans)
                break
    flag += ans
print(flag)
```
### 結果  
![](https://i.imgur.com/yNbJI3m.png)
* 從結果可以看到後面不足的部分就被補上了\x80\x00\x00...
>FLAG{31a7f10f1317f622}
## COR
### 題目分析
* 這題給了一個實作混合LFSR的檔案還有LFSR的輸出
* 把flag的內容分成三份分別當作三個LFSR的initial去產生三個LFSR然後用三個LFSR產生的結果去做運算來組合成新的LFSR
### 漏洞
* 因為這個LFSR是三個LFSR組合得到的結果但是這樣組合會有correlation的問題
* correlation指的是組合的LFSR出來的結果會跟單個LFSR產生的結果很類似相似度大概在75%上下
* 生成LFSR需要initial和feedback而且三個LFSR的feedback是已知的所以只要知道initial就能生成一樣的LFSR
### Exploit
* 因為有correlation的問題而且feedback已知所以可以一個一個暴力嘗試initial去看單個LFSR產生的結果跟組合的結果如果很相近那個可能就是生成那個LFSR的initial
* 因為flag的內容是可視字元所以拿來當作initial的內容會是兩個可視字元的組合所以就用兩個string.printable的組合去嘗試
* 這邊先測試LFSR3
```python=
from functools import reduce
import string

class LFSR:
    def __init__(self, init, feedback):
        self.state = init
        self.feedback = feedback
    def getbit(self):
        nextbit = reduce(lambda x, y: x ^ y, [i & j for i, j in zip(self.state, self.feedback)])
        self.state = self.state[1:] + [nextbit]
        return nextbit

def similarity(x, y):
    same = 0
    for i in range(100):
        if x[i] == y[i]:
            same += 1
    if (same/100) >= 0.7:
        print((same/100))
        return True
    else:
        return False

output = [1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1]

for i in string.printable:
    for j in string.printable:
        test = (i+j).encode()
        lfsr = LFSR([int(i) for i in f"{int.from_bytes(test, 'big'):016b}"], [int(i) for i in f'{52453:016b}'])   # test for LFSR3
        # lfsr = LFSR([int(i) for i in f"{int.from_bytes(test, 'big'):016b}"], [int(i) for i in f'{40111:016b}'])     # test for LFSR2
        if similarity([lfsr.getbit() for _ in range(100)], output):
            print(test)
```
* 測試LFSR3的結果  
![](https://i.imgur.com/QCkOZjn.png)
* 從結果可以看到當內容為`hj`時相似度有0.81而且只有一個結果所以這個可能就是LFSR3的initial
* 再來用相同方法測試LFSR2  
![](https://i.imgur.com/22UNfMc.png)
* 這邊測試出來有兩個結果分別是`ui`和`Vi`與output的相似度分別是0.78和0.7因為沒辦法確定哪個才是正確的所以只能兩個都試
* 再來要測試LFSR1就直接用剛才測試LFSR2和LFSR3的結果分別產生LFSR然後和LFSR1組合起來去找看有沒有和output完全相同的如果找到完全相同的就表示把所有LFSR的initial都找出來了
* 這邊把三個LFSR組合起來去看產生的結果
```python=
from functools import reduce
import string

class LFSR:
    def __init__(self, init, feedback):
        self.state = init
        self.feedback = feedback
    def getbit(self):
        nextbit = reduce(lambda x, y: x ^ y, [i & j for i, j in zip(self.state, self.feedback)])
        self.state = self.state[1:] + [nextbit]
        return nextbit

class MYLFSR:
    def __init__(self, inits):
        inits = [[int(i) for i in f"{int.from_bytes(init, 'big'):016b}"] for init in inits]
        self.l1 = LFSR(inits[0], [int(i) for i in f'{39989:016b}'])
        self.l2 = LFSR(inits[1], [int(i) for i in f'{40111:016b}'])
        self.l3 = LFSR(inits[2], [int(i) for i in f'{52453:016b}'])
    def getbit(self):
        x1 = self.l1.getbit()
        x2 = self.l2.getbit()
        x3 = self.l3.getbit()
        return (x1 & x2) ^ ((not x1) & x3)
    def getbyte(self):
        b = 0
        for i in range(8):
            b = (b << 1) + self.getbit()
        return bytes([b])

def similarity(x, y):
    if x == y:
        return True

output = [1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1]

for i in string.printable:
    for j in string.printable:
        test = (i+j).encode()
        lfsr = MYLFSR([test, b'ui', b'hj'])
        if similarity([lfsr.getbit() for _ in range(100)], output):
            print(test)
```
* 最後測試之後會發現當LFSR1的initial是`df`而LFSR2的是`ui`和LFSR3是`hj`時三個組合起來LFSR的getbit產生的結果和output完全相同
* 所以就知道三個的initial分別是`df`、`ui`和`hj`組合起來就變成了flag
>FLAG{dfuihj}