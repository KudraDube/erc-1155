// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============ BORROWED FROM OPENZEPPELIN ============
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract TieredPass1155 is ERC1155, AccessControl, Pausable {
    using ECDSA for bytes32;

    // ============ CUSTOM LOGIC: state ============
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    // tier id => max that can ever be minted for that tier (0 = uncapped, not set)
    mapping(uint256 => uint256) public maxSupply;
    // tier id => how many have been minted so far (lifetime total, burns do not reduce it)
    mapping(uint256 => uint256) public totalMinted;
    // nonce => already used? stops a signed authorisation being replayed
    mapping(uint256 => bool) public usedNonces;

    event MaxSupplySet(uint256 indexed tierId, uint256 cap);
    event Minted(address indexed to, uint256 indexed tierId, uint256 amount, uint256 nonce);

    constructor(string memory uri_, address admin, address signer)
        ERC1155(uri_)
    {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(SIGNER_ROLE, signer);
    }

    // ============ CUSTOM LOGIC: admin ============
    function setMaxSupply(uint256 tierId, uint256 cap) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(cap >= totalMinted[tierId], "cap below already minted");
        maxSupply[tierId] = cap;
        emit MaxSupplySet(tierId, cap);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }

    // ============ CUSTOM LOGIC: the signature scheme ============
    // The deadline is part of the signed data, so a signature cannot be reused after it expires
    // and the caller cannot change the deadline without invalidating the signature.
    function _hashMintRequest(address to, uint256 tierId, uint256 amount, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encodePacked(to, tierId, amount, nonce, deadline, address(this), block.chainid)
        );
        return MessageHashUtils.toEthSignedMessageHash(structHash);
    }

    function mintWithSignature(
        uint256 tierId,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external whenNotPaused {
        require(block.timestamp <= deadline, "signature expired");
        require(!usedNonces[nonce], "nonce already used");

        bytes32 digest = _hashMintRequest(msg.sender, tierId, amount, nonce, deadline);
        address recovered = digest.recover(signature);
        require(hasRole(SIGNER_ROLE, recovered), "invalid signature");

        // early check for a clear error message. _update enforces the same cap again below.
        uint256 cap = maxSupply[tierId];
        require(cap == 0 || totalMinted[tierId] + amount <= cap, "exceeds tier supply");

        // effects before interaction: mark the nonce used BEFORE the external-facing _mint
        // call (CEI pattern). totalMinted is updated inside _update, which _mint calls.
        usedNonces[nonce] = true;

        _mint(msg.sender, tierId, amount, "");
        emit Minted(msg.sender, tierId, amount, nonce);
    }

    // ============ CUSTOM LOGIC: accounting and the cap at the lowest level ============
    // _update is ERC1155's internal hook that EVERY mint, burn and transfer
    // routes through. totalMinted is increased HERE, not in mintWithSignature, so any
    // future mint path (a batch mint, an airdrop function) is counted and capped automatically.
    function _update(address from, address to, uint256[] memory ids, uint256[] memory values)
        internal
        override
    {
        super._update(from, to, ids, values);

        if (from == address(0)) {
            // this is a mint (from == zero address)
            for (uint256 i = 0; i < ids.length; i++) {
                uint256 tierId = ids[i];
                totalMinted[tierId] += values[i];
                uint256 cap = maxSupply[tierId];
                require(cap == 0 || totalMinted[tierId] <= cap, "tier supply exceeded");
            }
        }
    }

    // ============ REQUIRED OVERRIDE: multiple inheritance resolution ============
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC1155, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
