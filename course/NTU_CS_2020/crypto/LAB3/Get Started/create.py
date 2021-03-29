from web3 import Web3, HTTPProvider
import json
import time

w3 = Web3(HTTPProvider('https://ropsten.infura.io/v3/15253aad1d464c0ea37c6a342fe0e1b3'))
account = w3.toChecksumAddress('0xf75ad09Aea6569e0d54Ccde65b655A598e9b66E4')
w3.eth.defaultAccount = account
privateKey = bytes.fromhex('40a8d082c7e38882d20e7bf174d3a9ea246c82073c7f7f061f4f6bb78bfdbf55')
factoryAddr = w3.toChecksumAddress('0x16cf9e5a5848E40E27751f1c9277291993fE6C4E')
factory = w3.eth.contract(address=factoryAddr, abi=json.loads(open('./GetStartedFactory.abi').read()))

instances = factory.functions.instances(account).call()
if instances == '0x0000000000000000000000000000000000000000':
    txn = factory.functions.create().buildTransaction({
        'nonce':w3.eth.getTransactionCount(account),
        'gas':factory.functions.create().estimateGas(),
        'gasPrice':w3.toWei(1000, 'Gwei')
    })
    signed_txn = w3.eth.account.signTransaction(txn, private_key=privateKey)
    tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    instances = factory.functions.instances(account).call()
    print('create a new transaction successfully!!')
    print('wait for the transaction scuuess to get the instances...')
    timer = 0
    while(instances == '0x0000000000000000000000000000000000000000'):
        instances = factory.functions.instances(account).call()
        time.sleep(1)
        timer += 1
        if timer > 300:
            print('wait too long...')
            exit(0)
print(f'instnaces = {instances}')

instance = w3.eth.contract(address=instances, abi=json.loads(open('./GetStarted.abi').read()))
txn = instance.functions.callme().buildTransaction({'nonce':w3.eth.getTransactionCount(account), 'gas':instance.functions.callme().estimateGas(), 'gasPrice':w3.toWei(1000, 'Gwei')})
signedTxn = w3.eth.account.signTransaction(txn, private_key=privateKey)
txHash = w3.eth.sendRawTransaction(signedTxn.rawTransaction)
print('callme() transaction has been created successfully!!')
print('wait for win become true...')
while(1):
    if instance.functions.win().call() == True:
        print('win has become true!!')
        break
    time.sleep(1)