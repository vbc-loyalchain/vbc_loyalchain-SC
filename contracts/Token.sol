// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Token is ERC20{
    address public superAdmin;

    mapping (address => bool) public admins;

    constructor(string memory name_, string memory symbol_, address[] memory admins_) ERC20(name_, symbol_) {
        superAdmin = msg.sender;
        _mint(superAdmin, 10000 ether);

        uint256 numberOf_admins = admins_.length;
        for(uint8 i = 0; i < numberOf_admins; i++) {
            admins[admins_[i]] = true; 
            _mint(admins_[i], 10000 ether);
        }
    }

    modifier onlyAdmin() {
        require(admins[msg.sender] || msg.sender == superAdmin, "Only admin can call this function");
        _;
    }

    modifier onlySuperAdmin() {
        require(msg.sender == superAdmin, "Only super admin can call this function");
        _;
    }

    function changeAdmin(address account, bool isAllowed) external onlySuperAdmin {
        admins[account] = isAllowed;
    }

    function mintToken(uint256 amount) external  onlyAdmin {
        _mint(msg.sender, amount);
    }
}