// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Faucet {
    address private admin;
    constructor(){
        admin = msg.sender;
    }
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this function");
        _;
    }
    mapping(address userAddress => mapping(address tokenAddress => uint256)) public timeLockUserToken;

    function faucetToken(address userAddress, address tokenAddress, uint256 amount) external  {
        require(timeLockUserToken[userAddress][tokenAddress] == 0 || block.timestamp > timeLockUserToken[userAddress][tokenAddress], 
            "Each address can only receive faucet tokens once every 24 hours.");
        require(amount <= 20, "Only a maximum of 20 tokens can be fauceted at a time.");
        

        ERC20 token = ERC20(tokenAddress);
        require(token.balanceOf(address(this)) > amount * (1 ether), "Unable to faucet at the moment");
        token.transfer(userAddress, amount * (1 ether));
        timeLockUserToken[userAddress][tokenAddress] = block.timestamp + 24 hours;
    }

    function withdrawToken(address tokenAddress, uint256 amount) external onlyAdmin {
        ERC20 token = ERC20(tokenAddress);
        token.transfer(admin, amount);
    }
}