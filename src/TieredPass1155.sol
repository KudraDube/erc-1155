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
    // tier id => how many have been minted so far
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
    function _hashMintRequest(address to, uint256 tierId, uint256 amount, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encodePacked(to, tierId, amount, nonce, address(this), block.chainid)
        );
        return MessageHashUtils.toEthSignedMessageHash(structHash);
    }

    function mintWithSignature(
        uint256 tierId,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external whenNotPaused {
        require(!usedNonces[nonce], "nonce already used");

        bytes32 digest = _hashMintRequest(msg.sender, tierId, amount, nonce);
        address recovered = digest.recover(signature);
        require(hasRole(SIGNER_ROLE, recovered), "invalid signature");

        uint256 cap = maxSupply[tierId];
        require(cap == 0 || totalMinted[tierId] + amount <= cap, "exceeds tier supply");

        // effects before interaction: mark nonce used and update accounting
        // BEFORE the external-facing _mint call (CEI pattern)
        usedNonces[nonce] = true;
        totalMinted[tierId] += amount;

        _mint(msg.sender, tierId, amount, "");
        emit Minted(msg.sender, tierId, amount, nonce);
    }

    // ============ CUSTOM LOGIC: enforcing the cap at the lowest level ============
    // _update is ERC1155's internal hook that EVERY mint, burn and transfer
    // routes through. Overriding it is a second, independent guard on the
    // supply cap - even if some future function forgets to check maxSupply
    // directly, this still catches it.
    function _update(address from, address to, uint256[] memory ids, uint256[] memory values)
        internal
        override
    {
        if (from == address(0)) {
            // this is a mint (from == zero address)
            for (uint256 i = 0; i < ids.length; i++) {
                uint256 cap = maxSupply[ids[i]];
                require(cap == 0 || totalMinted[ids[i]] <= cap, "tier supply exceeded");
            }
        }
        super._update(from, to, ids, values);
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