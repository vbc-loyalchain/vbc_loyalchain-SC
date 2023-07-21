// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


contract SwapTwoChain {
    enum Status {
        PENDING,
        WITHDRAWN,
        REFUNDED
    }

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
     * @param hashlock - Hash of secret key.
     * @param status - status of LockContract
     */
    struct LockContract{
        address sender;
        address receiver;
        ERC20 tokenContract;
        uint256 amount;
        string key;
        bytes32 hashlock;
        Status status;
    }


    /**
     * @dev Mapping of txID to lockContract in the lock.
     */
    mapping (bytes32 => LockContract) private transactions;


    /**
     * @dev Event cancel a transaction.
     * @param id Id of LockContract.
     * @param from Address of creator.
     */
    event created(bytes32 indexed id, address indexed from);

    /**
     * @dev Event cancel a transaction.
     * @param id Id of LockContract.
     * @param from Account that canceled transaction.
     * @param amount Amount token has been refunded.
     */
    event canceled(bytes32 indexed id, address indexed from, uint256 amount);


    /**
     * @dev Event when a account withdrawn token from transaction.
     * @param id Id of LockContract.
     * @param from Account that withdrawn token from transaction.
     * @param amount Amount token has been withdrawn.
     */
    event withdrawn(bytes32 indexed id, address indexed from, uint256 amount);

    modifier uniqueOrder(bytes32 id) {
        require(transactions[id].sender == address(0), "Duplicate transaction by id");
        _;
    }

    modifier orderExisted(bytes32 id) {
        require(transactions[id].sender != address(0), "This order doesn't exists");
        _;
    }

    modifier orderInProgress(bytes32 id) {
        require(transactions[id].status == Status.PENDING, "This transaction has been done");
        _;
    }


    /**
     * @dev Create a new lock contract.
     * @param id - ID of transaction in database which was hashed
     * @param receiver - Address of receiver. 
     * @param token - Address of token contract.
     * @param amount - Amount of token.
     * @param hashlock - Hash of secret key.
     * @param isSeller - true if is seller, false is buyer
     */
    function create(
        bytes32 id,
        address receiver,  
        address token, 
        uint256 amount,
        bytes32 hashlock,
        bool isSeller
    ) public uniqueOrder(id) {
        require(msg.sender != receiver, "Transaction invalid");
        bytes32 contractId = isSeller ? createContractId(id, msg.sender, receiver) : createContractId(id, receiver, msg.sender);
        
        transactions[contractId] = LockContract({
            sender: msg.sender,
            receiver: receiver,
            tokenContract: ERC20(token),
            amount: amount,
            key: "",
            hashlock: hashlock,
            status: Status.PENDING
        });

        require(transactions[contractId].tokenContract.transferFrom(msg.sender, address(this), amount), "Transfer to contract failed");
        emit created(contractId, msg.sender);
    }


    /** 
     * @dev Withdraw token from lock contract.
     * @param contractId - ID of transaction.
     * @param key - Secret key to unlock contract.
     */
    function withdraw(bytes32 contractId, string memory key) external orderExisted(contractId) orderInProgress(contractId) {
        LockContract storage exchangeTx = transactions[contractId];
        
        require(exchangeTx.receiver == msg.sender, "Only receiver can withdraw");
        require(keccak256(abi.encodePacked(key)) == exchangeTx.hashlock, "Incorrect key");

        require(exchangeTx.tokenContract.transfer(exchangeTx.receiver, exchangeTx.amount), "Withdraw failed");

        exchangeTx.key = key;
        exchangeTx.status = Status.WITHDRAWN;

        emit withdrawn(contractId, exchangeTx.receiver, exchangeTx.amount);
    }


    /**
     * 
     * @param contractId - ID of transaction.
     * @param nonce - Nonce of account.
     * @param signatureAdmin - Signature of admin on txID, address, nonce.
     */
    function refund(bytes32 contractId, uint256 nonce, bytes memory signatureAdmin) orderExisted(contractId) orderInProgress(contractId) external {
        
        bytes32 message = keccak256(abi.encodePacked(contractId, msg.sender, nonce));
        bytes32 messageHash = ECDSA.toEthSignedMessageHash(message);

        require(admin == ECDSA.recover(messageHash, signatureAdmin), "Invalid signature");
        
        LockContract storage exchangeTx = transactions[contractId];

        require(exchangeTx.tokenContract.transfer(exchangeTx.sender,  exchangeTx.amount), "Refund failed");

        exchangeTx.status = Status.REFUNDED;
        
        emit canceled(contractId, exchangeTx.sender, exchangeTx.amount);
    }

    /**
     * @dev Checks whether the lock contract is in progress or not.
     * @param contractId - ID of transaction.
     */
    function isInProgress(bytes32 contractId) external view orderExisted(contractId) returns(bool) {
        LockContract memory exchangeTx = transactions[contractId];
        return exchangeTx.status == Status.PENDING;
    }

    /** 
     * @dev Get secret key of lock contract 
     * @param contractId - ID of transaction.
     */
    function getSecretKey(bytes32 contractId) external view orderExisted(contractId) returns(string memory) {
        require(msg.sender == transactions[contractId].sender, "Only owner can get secret key");
        return transactions[contractId].key;
    }

    /**
     * @dev Create contractId
     * @param id - ID of transaction in database which was hashed.
     * @param sender.
     * @param receiver.
     */
    function createContractId(bytes32 id, address sender, address receiver) internal pure returns(bytes32) {
        return keccak256(abi.encodePacked(id, sender, receiver));
    }
}