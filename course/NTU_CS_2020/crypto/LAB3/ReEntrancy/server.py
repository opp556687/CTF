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
    FACTORY_ADDRESS = {'ropsten': '0x84Fb598A7E8d58715d3C5F2E789570D7B5B0e290', 'rinkeby': '0x13DE18B85Fa41cBb9bdaEbC671affc5c08643462'}[network]
    FACTORY_ABI = json.loads(open('./ReEntrancyFactory.abi').read())

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