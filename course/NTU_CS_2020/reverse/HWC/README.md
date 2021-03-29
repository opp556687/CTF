---
tags: 2020 程式安全
---
# HWC
## gift
### 分析
* 直接拉進ida裡面分析  
![](https://i.imgur.com/wSQH2FD.png)
* 這邊會看到要輸入一串256個byte的字輸入完之後會去做比較如果比較結果相同就會去把data段裡面的一個table裡面的資料拿來跟要求的字串做xor之後會把xor之後的結果輸出
* 輸入題目要求的字串之後會發現他會輸出很多看起來很像垃圾的東西  
![](https://i.imgur.com/VAEeXcs.jpg)
* 嘗試把這些資料寫入到檔案裡面之後會發現他變成壓縮檔的樣子  
![](https://i.imgur.com/G0XQ9Wc.png)
* 用file看一下會發現他真的是壓縮檔  
![](https://i.imgur.com/AlnxHnT.png)
* 把它解壓縮出來又會得到另外一個新的檔案內容跟gift一樣是要輸入一個字串然後又會得到另外一個壓縮檔
* 所以他就是裡面一個壓縮檔又包另一個壓縮檔這樣一層一層的
### Exploit
* 既然知道他是壓縮檔了然後也知道要怎麼做就直接寫個shell script去爆他
```shell=
#!/bin/bash
for ((i=1; i<500; i++))
do
    chmod +x d
    strings -n 256 d | ./d > d.gz
    gunzip -f d.gz
done
```
* 一直跑到最後會他就沒辦法再解壓縮這時候就是最後一層了  
![](https://i.imgur.com/2vP0rMz.png)
* 最後會得到一個elf檔再把這個檔案拉進ida裡面分析會發現他跟前面都一樣要輸入一個要求的字串但是這次不是亂數是要輸入`@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@terrynini@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@`輸入完之後就能拿到flag了  
![](https://i.imgur.com/iN5YWdU.png)
>FLAG{what_a_boaring_challnge_but_you_did_it_yeah_yeah}
## JustOnLinux
### 分析
* 這題是static link而且被stripped過的  
![](https://i.imgur.com/WcfXa9s.png)
* 一樣直接ida裡面分析然後稍微替被stripped的系統函數命名會發現他會做一連串很複雜的操作之後會把結果輸出出來然後可以看到錯誤訊息裡面有`usage: babyencode string`所以可以猜他可能是某種encode  
![](https://i.imgur.com/nDuBHFy.png)
* 因為她會做右移和&0x3F的操作看起來蠻特別的所以就把`>> 18) & 0x3F`直接google查一下會發現這個是base64在做encode時的操作所以就知道這是在做base64的encode
* 一般的base64是由A-Z、a-z、數字0-9組成的因為她encode的table是由`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`組成的
* 但是這邊在ida裡面會看到有個`Vwxyzabcdefghi`的table裡面紀錄的是base64 encode時用的table因為她是用這個table來做encode所以會有一些?!:之類的標點符號
### Exploit
* 既然已經是base64的encode所以就直接找別人寫好的base64 decoder然後把table換掉就可以直接decode了
* decode完之後就能夠拿到flag了
```cpp=
#include <iostream>
#include <cstring>
#include <vector>
using namespace std;

const string Base64Table = "vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~o";

void write(int j, char *simbol)
{
    int k = 0;
    while (k < j + 1)
    {
        cout << simbol[k];
        k++;
    }
}

int getInt(const string &Base64Table, const string &inp, int i)
{
    int j;
    j = 0;
    while (Base64Table[j] != inp[i])
    {
        j++;
    }
    return j;
}

char *Decodding(const string &Base64Table, const string &inp)
{
    int longs;
    int i = 0, j = 0, bytes, ch = 1;
    char *simbol = new char[500];

    longs = inp.size();
    while ((longs / 4) > ch)
    {
        ch++;
        bytes = (getInt(Base64Table, inp, i) << 2) + ((getInt(Base64Table, inp, i + 1) >> 4));
        simbol[j] = char(bytes);
        j++;
        i++;

        bytes = ((getInt(Base64Table, inp, i) << 4)) + (getInt(Base64Table, inp, i + 1) >> 2);
        simbol[j] = char(bytes);
        i++;
        j++;

        bytes = ((getInt(Base64Table, inp, i) << 6)) + (getInt(Base64Table, inp, i + 1));
        simbol[j] = char(bytes);
        i = i + 2;
        j++;
    }

    bytes = (getInt(Base64Table, inp, i) << 2) + ((getInt(Base64Table, inp, i + 1) >> 4));
    simbol[j] = char(bytes);
    i++;
    if (inp[i + 1] != '=')
    {
        j++;
        bytes = ((getInt(Base64Table, inp, i) << 4)) + (getInt(Base64Table, inp, i + 1) >> 2);
        simbol[j] = char(bytes);
        i++;
        if (inp[i + 1] != '=')
        {
            j++;
            bytes = ((getInt(Base64Table, inp, i) << 6)) + (getInt(Base64Table, inp, i + 1));
            simbol[j] = char(bytes);
        }

        write(j, simbol);
    }
}

int main()
{
    string inp = "M&=wM].]VyA?GR&[GRA%I]Q#HOA_GRz/T%M?H?T@UR_%HBL?GRA.U?w>HSM*WS@ ";

    Decodding(Base64Table, inp);

    return 0;
}
```
>FLAG{7h1s-i5-ac7ua11y-a-b4s364enc0d3-alg0r1thm}