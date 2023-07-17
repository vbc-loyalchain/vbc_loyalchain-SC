// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


contract SwapTwoChain {
    /**
     * @dev Address of admin.
     */
    address private admin; 


    /**
     * @dev Set admin when deploy contract.
     */
    constructor() {
        admin = msg.sender;
    }


    /**
     * @dev Struct of lock contract.
     * @param sender - Address of sender.
     * @param receiver - Address of receiver.
     * @param tokenContract - Address of token contract.
     * @param amount - Amount of token.
     * @param key - Secret key to lock contract.
     * @param hashlock - Hash of secret key.
     * @param timelock - Time to lock contract.
     * @param withdrawn - Status of withdrawn.
     * @param refunded - Status of refunded.
     */
    struct LockContract{
        address sender;
        address receiver;
        ERC20 tokenContract;
        uint256 amount;
        string key;
        bytes32 hashlock;
        uint256 timelock;
        bool withdrawn;
        bool refunded;
    }


    /**
     * @dev Mapping of txID to lockContract in the lock.
     */
    mapping (string => LockContract) private transactions;


    /**
     * @dev Event cancel a transaction.
     * @param from Account that canceled transaction.
     * @param amount Amount token has been refunded.
     */
    event canceled(address from, uint256 amount);


    /**
     * @dev Event when a account withdrawn token from transaction.
     * @param from Account that withdrawn token from transaction.
     * @param amount Amount token has been withdrawn.
     */
    event withdrawn(address from, uint256 amount);


    /**
     * @dev Create a new lock contract.
     * @param id txID - ID of transaction
     * @param receiver - Address of receiver. 
     * @param token - Address of token contract.
     * @param amount - Amount of token.
     * @param key - Secret key to lock contract.
     * @param hashlock - Hash of secret key.
     * @param timelock - Time to lock contract.
     */
    function create(
        string memory id,
        address receiver,  
        address token, 
        uint256 amount,
        string memory key,
        bytes32 hashlock, 
        uint256 timelock
    ) public returns (bool) {
        require(transactions[id].sender == address(0), "Duplicate transaction by id");
        require(msg.sender != receiver, "Transaction invalid");
        
        transactions[id] = LockContract({
            sender: msg.sender,
            receiver: receiver,
            tokenContract: ERC20(token),
            amount: amount,
            key: key,
            hashlock: hashlock,
            timelock: block.timestamp + 60 * 60 * timelock,
            withdrawn: false,
            refunded: false
        });

        transactions[id].tokenContract.transferFrom(msg.sender, address(this), amount);
        return true;
    }


    /** 
     * @dev Withdraw token from lock contract.
     * @param txId - ID of transaction.
     * @param _key - Secret key to unlock contract.
     */
    function withdraw(string memory txId, string memory _key) external {
        LockContract storage exchangeTx = transactions[txId];
        
        require(exchangeTx.refunded == false, "Transaction has been canceled");
        require(exchangeTx.withdrawn == false, "Transaction has been withdrawn");
        require(exchangeTx.receiver == msg.sender, "Only receiver can withdraw");
        require(keccak256(abi.encodePacked(_key)) == exchangeTx.hashlock, "Incorrect key");

        exchangeTx.tokenContract.transfer(exchangeTx.receiver, exchangeTx.amount);
        exchangeTx.key = _key;
        exchangeTx.withdrawn = true;

        emit withdrawn(exchangeTx.receiver, exchangeTx.amount);
    }


    /**
     * 
     * @param txId - ID of transaction.
     * @param nonce - Nonce of account.
     * @param signatureAdmin - Signature of admin on txID, address, nonce.
     */
    function refund(string memory txId, uint256 nonce, bytes memory signatureAdmin) external {
        
        bytes32 message = keccak256(abi.encodePacked( txId, msg.sender, nonce));
        bytes32 messageHash = ECDSA.toEthSignedMessageHash(message);
        require(admin == ECDSA.recover(messageHash, signatureAdmin), "Invalid signature");
        
        LockContract storage exchangeTx = transactions[txId];
        require(exchangeTx.withdrawn == false 
                && exchangeTx.refunded == false, "Can't refund");
        require(exchangeTx.timelock <= block.timestamp, "Too early to refund");

        exchangeTx.tokenContract.transfer(exchangeTx.sender,  exchangeTx.amount);
        exchangeTx.refunded = true;
        
        emit canceled(exchangeTx.sender, exchangeTx.amount);
    }


    /**
     * @dev Get sceret key of lock contract.
     * @param txId - ID of transaction.
     */
    function getSecretKey(string memory txId) public view returns (string memory) {
        require(transactions[txId].sender != address(0), "This transaction doesn't exists");
        require(transactions[txId].sender == msg.sender, "Only owner can get the secret key");
        return transactions[txId].key;
    }


    /**
     * @dev Checks whether the lock contract is over.
     * @param txId - ID of transaction.
     */
    function isEndLockContract(string memory txId) public view returns(bool) {
        require(transactions[txId].sender != address(0), "This transaction doesn't exists");
        LockContract memory exchangeTx = transactions[txId];
        if (exchangeTx.timelock <= block.timestamp)
            return true;
        else return false;
    }

    /**
     * @dev Checks whether the lock contract is refunded.
     * @param txId - ID of transaction.
     */
    function isRefunded(string memory txId) public view returns(bool) {
        require(transactions[txId].sender != address(0), "This transaction doesn't exists");
        LockContract memory exchangeTx = transactions[txId];
        return exchangeTx.refunded;
    }
} 