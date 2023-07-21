// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Swapper {
    enum Status {
        PENDING,
        COMPLETED,
        REFUNDED
    }

    struct Order {
        address from;
        ERC20 token_from;
        ERC20 token_to;
        uint256 amount_from;
        uint256 amount_to;
        Status status;
    }

    mapping(bytes32 => Order) public transactions;

    event created(bytes32 indexed txId, address indexed from);

    event canceled(bytes32 indexed txId, address indexed from, uint256 amount);

    event accepted(bytes32 indexed txId, address indexed to, uint256 amount);

    event swapSuccessfully(bytes32 indexed txId, address indexed from, address indexed to);

    modifier uniqueOrder(bytes32 id) {
        require(transactions[id].from == address(0), "Duplicate order by id");
        _;
    }

    modifier orderExisted(bytes32 id) {
        require(transactions[id].from != address(0), "This order doesn't exists");
        _;
    }

    modifier orderInProgress(bytes32 id) {
        require(transactions[id].status == Status.PENDING, "This transaction has been done");
        _;
    }

    constructor() {}

    function createTx(
        bytes32 id, 
        address tokenFrom, 
        address tokenTo, 
        uint256 amountFrom, 
        uint256 amountTo
    ) public uniqueOrder(id) {
        require(tokenFrom != tokenTo, "Only swap between two different token");
        transactions[id] = Order({
            from: msg.sender,
            token_from: ERC20(tokenFrom),
            token_to: ERC20(tokenTo),
            amount_from: amountFrom,
            amount_to: amountTo,
            status: Status.PENDING
        });

        require(transactions[id].token_from.transferFrom(msg.sender, address(this), transactions[id].amount_from), "Transfer to contract failed");
        emit created(id, msg.sender);
    }

    function acceptTx(bytes32 txId) orderExisted(txId) orderInProgress(txId) external { 
        Order storage exchangeTx = transactions[txId];

        require(exchangeTx.from != msg.sender, "Can't accept by your self! =))");
        
        require(exchangeTx.token_to.transferFrom(msg.sender, address(this), exchangeTx.amount_to), "Transfer to contract failed");

        swap(txId);

        emit accepted(txId, msg.sender, exchangeTx.amount_to);
    }

    function refund(bytes32 txId) orderExisted(txId) orderInProgress(txId) external {
        Order storage exchangeTx = transactions[txId];

        require(exchangeTx.from == msg.sender, "Only owner can refund this transaction");

        require(exchangeTx.token_from.transfer(exchangeTx.from,  exchangeTx.amount_from), "Refund failed");

        exchangeTx.status = Status.REFUNDED;

        emit canceled(txId, exchangeTx.from, exchangeTx.amount_from);
    }

    function swap(bytes32 txId) internal {
        Order storage exchangeTx = transactions[txId];
        
        require(exchangeTx.token_from.transfer(msg.sender, exchangeTx.amount_from), "Swap failed");
        require(exchangeTx.token_to.transfer(exchangeTx.from, exchangeTx.amount_to), "Swap failed");

        exchangeTx.status = Status.COMPLETED;

        emit swapSuccessfully(txId, exchangeTx.from, msg.sender);
    }
}