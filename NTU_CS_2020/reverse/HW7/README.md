---
tags: 2020 程式安全
---
# HW7
## Going Crazy
## 題目分析
* 題目給的是用golang寫而且被strip的binary所以用ida打開就會變下面這樣  
![](https://i.imgur.com/PJLr4fE.png)
* 雖然被strip了但是golang會把那些function的名字都存起來所以可以再還原回去這邊用[go_parser](https://github.com/0xjiayu/go_parser)來還原函數名還原後去找main.main就能找到入口點然後就可以開始逆了  
![](https://i.imgur.com/b0UTxJE.png)
* 一開始只有一連串的輸出之後會用fmt_Scanln來讀取輸入
* 讀完之後這邊會檢查輸入的第一個字和最後一個字是不是x檢查通過之後才會繼續往後執行  
![](https://i.imgur.com/himsFti.png)
* 接下來這邊把輸入的字串用`,`切開然後進入main_check_input裡面對輸入內容做檢查如果檢查通過會輸出CRAZY!CRAZIER!CRAZIEST!!不然會輸出ok然後再輸出no ! tOo NORmAL ! yoU hAvE To Be crAzY eNoUgh BeForE GEtTING flag然後再重新讀取輸入  
![](https://i.imgur.com/9sxHdOe.png)
* 之後進去看main_check_input在裡面會用到Atoi把剛剛用`,`切開的內容取一個出來做字串轉成數字然後丟進main_bezu裡面去運算而且這邊從取第幾個值來做Atoi的方式是透過另一個陣列裡面寫的去取的
* 然後會比較看看main_bezu裡面算出來的結果跟一個陣列裡面的值做比較看是不是都相等總共要比36次如果有一次不通過就會跳出然後去執行main裡面ok的部分  
![](https://i.imgur.com/i1CXQTu.png)
* 然後再進去看main_bezu會看到這邊把剛剛用Atoi轉出來的數字和0xFBC56A93還有0跟0當作參數傳進去main_rchvf裡面做運算  
![](https://i.imgur.com/y6QIZs9.png)
* 再進去看main_rchvf在做甚麼會發現是在做一連串很複雜的運算  
![](https://i.imgur.com/bDBbd72.png)
* 最後逆完會發現他是在算貝祖定理並且根據貝祖定理有說到如果ax+by = 1有整數解的話a b會互質這邊我們的輸入是a已經給出的0xFBC56A93是b然後算出來的結果就是x和y因為0xFBC56A93是質數a b一定互質所以一定會有整數解
* 題目就是要找出a然後跟0xFBC56A93去算算出來的整數解x要跟題目給的一樣
## Exploit
* 既然已經知道是在算貝祖定理了就直接上網找別人寫好的給a b就能算出解x y的程式來跑
* 然後這邊算出來的結果要放在第幾個位置上是有寫在另外一個陣列會把裡面的值i取出來然後做(((i<<4)/8)/2)得到的結果就是用a和0xFBC56A93算出來符合題目要求的a要放在第幾個位置
* 所以就直接寫個腳本下去爆把每個值都爆出來最後會變成70, 76, 65, 71, 123, 103...再把這些數字根據ascii去做轉換就能拿到flag了
```python=
def e(a, b):
    r = b
    x = a
    s = z = 0
    t = y = 1
    while r:
        q = x//r
        x, r = r, x % r
        y, s = s, y-q*s
        z, t = t, z-q*t
    return y % (b//x), z % (-a//x)

target = [0xc8f9a829, 0xec83260e, 0xaf93c6f4, 0x5a1b89d9, 0x31e68d0d, 0xc38ce7e7, 0xc8f9a829, 0x4aee907b, 0xe0138a5f, 0x31e68d0d, 0x9975e45, 0xd129ea43, 0xc6830a2f, 0xc8f9a829, 0xec83260e, 0xec83260e, 0x13bf2b7f, 0xe0138a5f,
          0xe419b183, 0xb2f1ddbb, 0xc38ce7e7, 0xc38ce7e7, 0x91639414, 0x5a1b89d9, 0x31e68d0d, 0x8c45c2b1, 0xc76c360, 0x876805b, 0x8d67dd2c, 0xc212d77c, 0xec83260e, 0x5a1b89d9, 0xe59d8403, 0x77244701, 0x1499761a, 0xeb6552fe]
index = [0xf, 0x20, 0x1, 0x1d, 0x17, 0x12, 0xe, 0x1f, 0x1a, 0x8, 0x1b, 0x2, 0x10, 0x14, 0x15, 0x22, 0x13,
         0x1c, 0x18, 0x16, 0x5, 0x7, 0x3, 0x19, 0x6, 0x0, 0xd, 0xc, 0x1e, 0xb, 0x21, 0x9, 0x23, 0xa, 0x11, 0x4]
decode = [0]*36
for i in range(36):
    a = 1
    while 1:
        if e(a, 0xfbc56a93)[0] == target[i]:
            decode[index[i] << 4//8//2] = a
            break
        a += 1
for i in range(36):
    print(f'{chr(decode[i])}', end='')
```
>FLAG{gogo_p0werr4ng3r!you_did_IT!!!}