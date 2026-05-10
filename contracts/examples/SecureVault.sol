// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @title SecureVault
 * @notice A well-secured vault contract for comparison.
 *         Demonstrates best practices that ChainGuard AI rewards.
 */

// Minimal ReentrancyGuard for demo (in production, use OpenZeppelin)
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

contract SecureVault is ReentrancyGuard {
    mapping(address => uint256) public balances;
    address public immutable owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender; // ✅ msg.sender, not tx.origin
    }

    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // ✅ Checks-Effects-Interactions + nonReentrant
    function withdraw(uint256 _amount) external nonReentrant {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // Effect first
        balances[msg.sender] -= _amount;

        // Interaction last
        (bool sent, ) = payable(msg.sender).call{value: _amount}("");
        require(sent, "Transfer failed");

        emit Withdrawal(msg.sender, _amount);
    }

    // ✅ Access-controlled emergency function
    function emergencyDrain(address payable _to) external onlyOwner {
        (bool sent, ) = _to.call{value: address(this).balance}("");
        require(sent, "Transfer failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
