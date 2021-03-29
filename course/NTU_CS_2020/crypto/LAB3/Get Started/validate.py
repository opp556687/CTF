from web3 import Web3, HTTPProvider
import json

w3 = Web3(HTTPProvider('https://ropsten.infura.io/v3/15253aad1d464c0ea37c6a342fe0e1b3'))
account = w3.toChecksumAddress('0xf75ad09Aea6569e0d54Ccde65b655A598e9b66E4')
w3.eth.defaultAccount = account
privateKey = bytes.fromhex('40a8d082c7e38882d20e7bf174d3a9ea246c82073c7f7f061f4f6bb78bfdbf55')
factoryAddr = w3.toChecksumAddress('0x16cf9e5a5848E40E27751f1c9277291993fE6C4E')
factory = w3.eth.contract(address=factoryAddr, abi=json.loads(open('./GetStartedFactory.abi').read()))
txn = factory.functions.validate(0x84e83614942dafe636d31b65fbe2060b523387ce7b56b4b23799aaa23f8e98ec).buildTransaction({'nonce':w3.eth.getTransactionCount(account), 'gas':factory.functions.validate(0x84e83614942dafe636d31b65fbe2060b523387ce7b56b4b23799aaa23f8e98ec).estimateGas(), 'gasPrice':w3.toWei(1000, 'Gwei')})
signTxn = w3.eth.account.signTransaction(txn, private_key=privateKey)
txnHash = w3.eth.sendRawTransaction(signTxn.rawTransaction)
print('transaction -> https://ropsten.etherscan.io/tx/' + hex(int.from_bytes(txnHash, 'big')))