// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Minimal ERC-20 for B7 post-execution verification e2e. No imports,
// no proxies: every Transfer/Approval log below is asserted against
// Assertara's authorized effect list on a real Anvil chain.
contract TestToken {
    string public name = "Test Token";
    string public symbol = "TT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        uint256 supply = 1_000_000 ether;
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        balanceOf[msg.sender] -= value;
        unchecked { balanceOf[to] += value; }
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        unchecked { balanceOf[to] += value; }
        emit Transfer(from, to, value);
        return true;
    }
}

// Fee-on-transfer variant: transfer(100) emits Transfer(95) +
// Transfer(5 to feeSink). Assertara authorizes the decoded 100-unit
// effect, so the genuine receipt MUST verify as EFFECTS_DIVERGED.
contract FeeToken {
    string public name = "Fee Token";
    string public symbol = "FEE";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public immutable feeSink;
    uint256 public constant FEE_BPS = 500;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(address sink) {
        feeSink = sink;
        uint256 supply = 1_000_000 ether;
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        uint256 fee = (value * FEE_BPS) / 10_000;
        uint256 net = value - fee;
        balanceOf[msg.sender] -= value;
        unchecked {
            balanceOf[to] += net;
            balanceOf[feeSink] += fee;
        }
        emit Transfer(msg.sender, to, net);
        emit Transfer(msg.sender, feeSink, fee);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        unchecked { balanceOf[to] += value; }
        emit Transfer(from, to, value);
        return true;
    }
}
