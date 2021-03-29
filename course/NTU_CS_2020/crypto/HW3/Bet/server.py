#!/usr/bin/env python3
import os
import time
import json
from web3 import Web3, WebsocketProvider
from config import *

FLAG = open('./flag').read()

def main():
    print('Choose a network.')
    print('1) ropsten')
    print('2) rinkeby')
    network = {'1': 'ropsten', '2': 'rinkeby'}[input('> ')]

    w3 = Web3(WebsocketProvider(f'wss://{network}.infura.io/ws/v3/{INFURA_PROJ_ID}'))
    FACTORY_ADDRESS = {'ropsten': '0x8e0a809B1f413deB6427535cC53383954DBF8329', 'rinkeby': '0xf754a30737b55aE136c3f2C85c0dDf872F55353B'}[network]
    FACTORY_ABI = json.loads(open('./BetFactory.abi').read())

    # generate unique token
    token = os.urandom(32).hex()
    print(f'Factory Contract Address : {FACTORY_ADDRESS}')
    print('1) call create() to generate new challenge instance')
    print(f'2) call validate(0x{token}) to get flag')
    print('----- flag will appear below -----')

    # watch for token in blockchain
    factory = w3.eth.contract(address=FACTORY_ADDRESS, abi=FACTORY_ABI)
    event_filter = factory.events.GetFlag.createFilter(fromBlock='latest', argument_filters={'token': int(token, 16)})
    while True:
        if event_filter.get_new_entries():
            print(FLAG)
            break
        time.sleep(1)

main()