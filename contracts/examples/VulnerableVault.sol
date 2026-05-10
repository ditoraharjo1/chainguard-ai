// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @notice Intentionally insecure contract for ChainGuard AI demo.
 *         DO NOT deploy — contains multiple known vulnerabilities.
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = tx.origin; // ⚠ tx.origin instead of msg.sender
    }

    // ⚠ Reentrancy: external call before state update
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // Vulnerable: sends ETH before updating balance
        (bool sent, ) = msg.sender.call{value: _amount}("");
        require(sent, "Transfer failed");

        balances[msg.sender] -= _amount;

        emit Withdrawal(msg.sender, _amount);
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // ⚠ No access control on sensitive function
    function emergencyDrain(address payable _to) external {
        _to.call{value: address(this).balance}("");
    }

    // ⚠ tx.origin auth
    function changeOwner(address _newOwner) public {
        require(tx.origin == owner, "Not owner");
        owner = _newOwner;
    }

    // ⚠ Dangerous selfdestruct — no protection
    function destroy() public {
        selfdestruct(payable(owner));
    }

    // ⚠ Unbounded loop — potential DoS
    address[] public depositors;

    function distributeRewards(uint256 _reward) public {
        for (uint256 i = 0; i < depositors.length; i++) {
            balances[depositors[i]] += _reward;
        }
    }

    // ⚠ Timestamp dependency
    function isLocked() public view returns (bool) {
        return block.timestamp < 1700000000;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
