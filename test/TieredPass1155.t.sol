// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC1155Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {TieredPass1155} from "../src/TieredPass1155.sol";

/// @dev Stands in for a FUTURE function that mints without checking the cap or counting supply.
///      The _update guard must still catch it.
contract PassHarness is TieredPass1155 {
    constructor(string memory uri_, address admin, address signer) TieredPass1155(uri_, admin, signer) {}

    function unsafeMint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount, "");
    }

    function unsafeMintBatch(address to, uint256[] memory ids, uint256[] memory amounts) external {
        _mintBatch(to, ids, amounts, "");
    }

    function unsafeBurn(address from, uint256 id, uint256 amount) external {
        _burn(from, id, amount);
    }
}

/// @dev A contract with no ERC1155 receiver hook. Minting to it must fail.
contract NoReceiver {
    function mint(TieredPass1155 pass, uint256 tierId, uint256 amount, uint256 nonce, uint256 deadline, bytes calldata sig)
        external
    {
        pass.mintWithSignature(tierId, amount, nonce, deadline, sig);
    }
}

/// @dev Tries to mint again with the same signature from inside the receiver hook.
contract ReentrantReceiver is ERC1155Holder {
    TieredPass1155 public pass;
    uint256 tierId;
    uint256 amount;
    uint256 nonce;
    uint256 deadline;
    bytes sig;
    bool public armed;
    bytes public lastError;

    function attack(
        TieredPass1155 pass_,
        uint256 tierId_,
        uint256 amount_,
        uint256 nonce_,
        uint256 deadline_,
        bytes calldata sig_
    ) external {
        pass = pass_;
        tierId = tierId_;
        amount = amount_;
        nonce = nonce_;
        deadline = deadline_;
        sig = sig_;
        armed = true;
        pass.mintWithSignature(tierId, amount, nonce, deadline, sig);
    }

    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes memory data)
        public
        override
        returns (bytes4)
    {
        if (armed) {
            armed = false;
            try pass.mintWithSignature(tierId, amount, nonce, deadline, sig) {}
            catch (bytes memory err) {
                lastError = err;
            }
        }
        return super.onERC1155Received(operator, from, id, value, data);
    }
}

/// @dev Holds the signer key and drives random mints, cap changes and transfers.
contract PassHandler is Test {
    TieredPass1155 public pass;
    address[] public actors;
    uint256 signerPk;
    uint256 nonceCounter;
    uint256 public constant TIERS = 3;

    constructor() {
        address signerAddr;
        (signerAddr, signerPk) = makeAddrAndKey("handlerSigner");
        pass = new TieredPass1155("ipfs://x/{id}.json", address(this), signerAddr); // the handler is the admin
        for (uint256 i = 0; i < 3; i++) {
            actors.push(makeAddr(string.concat("passActor", vm.toString(i))));
        }
    }

    function mint(uint256 actorSeed, uint256 tierSeed, uint256 amount) external {
        address actor = actors[actorSeed % actors.length];
        uint256 tierId = tierSeed % TIERS;
        amount = bound(amount, 1, 100);
        uint256 nonce = nonceCounter++;
        uint256 deadline = block.timestamp + 1 days;

        bytes32 hash = keccak256(abi.encodePacked(actor, tierId, amount, nonce, deadline, address(pass), block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, MessageHashUtils.toEthSignedMessageHash(hash));

        vm.prank(actor);
        try pass.mintWithSignature(tierId, amount, nonce, deadline, abi.encodePacked(r, s, v)) {} catch {}
    }

    function setCap(uint256 tierSeed, uint256 cap) external {
        cap = bound(cap, 0, 500);
        try pass.setMaxSupply(tierSeed % TIERS, cap) {} catch {}
    }

    function transferTokens(uint256 fromSeed, uint256 toSeed, uint256 tierSeed, uint256 amount) external {
        address from = actors[fromSeed % actors.length];
        address to = actors[toSeed % actors.length];
        uint256 tierId = tierSeed % TIERS;
        uint256 balance = pass.balanceOf(from, tierId);
        if (balance == 0) return;
        amount = bound(amount, 1, balance);
        vm.prank(from);
        pass.safeTransferFrom(from, to, tierId, amount, "");
    }

    function passTime(uint256 secondsToWait) external {
        vm.warp(block.timestamp + bound(secondsToWait, 1, 2 days));
    }

    function sumOfBalances(uint256 tierId) external view returns (uint256 sum) {
        for (uint256 i = 0; i < actors.length; i++) {
            sum += pass.balanceOf(actors[i], tierId);
        }
    }
}

contract TieredPass1155Test is Test {
    TieredPass1155 pass;
    PassHarness harness;
    PassHandler handler;

    address admin = makeAddr("admin");
    address signer;
    uint256 signerPk;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address stranger = makeAddr("stranger");

    uint256 constant GOLD = 1;
    uint256 constant SILVER = 2;
    uint256 nextNonce = 1;

    event MaxSupplySet(uint256 indexed tierId, uint256 cap);
    event Minted(address indexed to, uint256 indexed tierId, uint256 amount, uint256 nonce);
    event TransferSingle(
        address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value
    );

    function setUp() public {
        (signer, signerPk) = makeAddrAndKey("signer");
        pass = new TieredPass1155("ipfs://tiers/{id}.json", admin, signer);
        harness = new PassHarness("ipfs://tiers/{id}.json", admin, signer);

        handler = new PassHandler();
        targetContract(address(handler));
    }

    // helpers

    function _deadline() internal view returns (uint256) {
        return block.timestamp + 1 hours;
    }

    /// @dev Builds the digest exactly the way the contract does.
    function _digest(address pass_, address to, uint256 tierId, uint256 amount, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 hash = keccak256(abi.encodePacked(to, tierId, amount, nonce, deadline, pass_, block.chainid));
        return MessageHashUtils.toEthSignedMessageHash(hash);
    }

    function _sign(
        uint256 pk,
        address pass_,
        address to,
        uint256 tierId,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _digest(pass_, to, tierId, amount, nonce, deadline));
        return abi.encodePacked(r, s, v); // order is r then s then v
    }

    /// @dev Signs with the real signer and mints as `user`. Returns the nonce used.
    function _mintFor(address user, uint256 tierId, uint256 amount) internal returns (uint256 nonce) {
        nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), user, tierId, amount, nonce, deadline);
        vm.prank(user);
        pass.mintWithSignature(tierId, amount, nonce, deadline, sig);
    }

    // constructor and interfaces

    function test_constructor_grantsRoles() public view {
        assertTrue(pass.hasRole(pass.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(pass.hasRole(pass.SIGNER_ROLE(), signer));
        assertFalse(pass.hasRole(pass.SIGNER_ROLE(), admin)); // the admin is not automatically a signer
        assertFalse(pass.hasRole(pass.DEFAULT_ADMIN_ROLE(), signer));
    }

    function test_constructor_setsUri() public view {
        assertEq(pass.uri(GOLD), "ipfs://tiers/{id}.json");
    }

    function test_supportsInterface() public view {
        assertTrue(pass.supportsInterface(0x01ffc9a7)); // ERC165
        assertTrue(pass.supportsInterface(0xd9b67a26)); // ERC1155
        assertTrue(pass.supportsInterface(0x7965db0b)); // AccessControl
        assertFalse(pass.supportsInterface(0xffffffff));
    }

    // admin: setMaxSupply, pause

    function test_setMaxSupply_setsCapAndEmits() public {
        vm.expectEmit(true, false, false, true);
        emit MaxSupplySet(GOLD, 100);
        vm.prank(admin);
        pass.setMaxSupply(GOLD, 100);

        assertEq(pass.maxSupply(GOLD), 100);
        assertEq(pass.maxSupply(SILVER), 0); // other tiers untouched
    }

    function test_setMaxSupply_onlyAdmin() public {
        bytes32 adminRole = pass.DEFAULT_ADMIN_ROLE();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, adminRole
            )
        );
        pass.setMaxSupply(GOLD, 100);

        // the signer is not an admin either
        vm.prank(signer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, signer, adminRole
            )
        );
        pass.setMaxSupply(GOLD, 100);
    }

    function test_setMaxSupply_cannotGoBelowAlreadyMinted() public {
        _mintFor(alice, GOLD, 10);

        vm.prank(admin);
        vm.expectRevert("cap below already minted");
        pass.setMaxSupply(GOLD, 9);

        vm.prank(admin);
        pass.setMaxSupply(GOLD, 10); // exactly the minted amount is allowed
        assertEq(pass.maxSupply(GOLD), 10);
    }

    function test_pause_onlyAdmin() public {
        bytes32 adminRole = pass.DEFAULT_ADMIN_ROLE();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, adminRole
            )
        );
        pass.pause();

        vm.prank(admin);
        pass.pause();

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, adminRole
            )
        );
        pass.unpause();
    }

    function test_pause_blocksMintingUntilUnpaused() public {
        vm.prank(admin);
        pass.pause();

        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 1, nonce, deadline);
        vm.prank(alice);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);

        vm.prank(admin);
        pass.unpause();
        vm.prank(alice);
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig); // the same signature now works
        assertEq(pass.balanceOf(alice, GOLD), 1);
    }

    function test_pause_doesNotFreezeTransfers() public {
        // Documents current behaviour: pause stops NEW mints only. Holders can still trade.
        _mintFor(alice, GOLD, 5);
        vm.prank(admin);
        pass.pause();

        vm.prank(alice);
        pass.safeTransferFrom(alice, bob, GOLD, 2, "");
        assertEq(pass.balanceOf(bob, GOLD), 2);
    }

    // mintWithSignature: happy path

    function test_mint_givesTokensAndRecordsSupply() public {
        uint256 nonce = _mintFor(alice, GOLD, 3);

        assertEq(pass.balanceOf(alice, GOLD), 3);
        assertEq(pass.totalMinted(GOLD), 3);
        assertTrue(pass.usedNonces(nonce));
    }

    function test_mint_emitsEvents() public {
        uint256 nonce = nextNonce;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 3, nonce, deadline);

        vm.expectEmit(true, true, true, true);
        emit TransferSingle(alice, address(0), alice, GOLD, 3);
        vm.expectEmit(true, true, false, true);
        emit Minted(alice, GOLD, 3, nonce);
        vm.prank(alice);
        pass.mintWithSignature(GOLD, 3, nonce, deadline, sig);
    }

    function test_mint_tiersAreIndependent() public {
        _mintFor(alice, GOLD, 3);
        _mintFor(alice, SILVER, 7);

        assertEq(pass.balanceOf(alice, GOLD), 3);
        assertEq(pass.balanceOf(alice, SILVER), 7);
        assertEq(pass.totalMinted(GOLD), 3);
        assertEq(pass.totalMinted(SILVER), 7);
    }

    function test_mint_totalMintedAccumulatesAcrossUsers() public {
        _mintFor(alice, GOLD, 3);
        _mintFor(bob, GOLD, 4);

        assertEq(pass.totalMinted(GOLD), 7);
    }

    function test_mint_signatureWorksAtExactlyTheDeadline() public {
        uint256 nonce = nextNonce++;
        uint256 deadline = block.timestamp + 100;
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 1, nonce, deadline);

        vm.warp(deadline);
        vm.prank(alice);
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
        assertEq(pass.balanceOf(alice, GOLD), 1);
    }

    // mintWithSignature: the signature checks

    function test_mint_revertsAfterTheDeadline() public {
        uint256 nonce = nextNonce++;
        uint256 deadline = block.timestamp + 100;
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 1, nonce, deadline);

        vm.warp(deadline + 1);
        vm.prank(alice);
        vm.expectRevert("signature expired");
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
    }

    function test_mint_deadlineCannotBeExtendedByTheCaller() public {
        uint256 nonce = nextNonce++;
        uint256 signedDeadline = block.timestamp + 100;
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 1, nonce, signedDeadline);

        vm.warp(signedDeadline + 1);
        vm.prank(alice);
        vm.expectRevert("invalid signature"); // a new deadline means the signature no longer matches
        pass.mintWithSignature(GOLD, 1, nonce, signedDeadline + 1 days, sig);
    }

    function test_mint_replayWithSameNonceReverts() public {
        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 1, nonce, deadline);

        vm.startPrank(alice);
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
        vm.expectRevert("nonce already used");
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
        vm.stopPrank();

        assertEq(pass.balanceOf(alice, GOLD), 1); // only minted once
    }

    function test_mint_signatureFromWrongKeyReverts() public {
        (, uint256 attackerPk) = makeAddrAndKey("attacker");
        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(attackerPk, address(pass), alice, GOLD, 1, nonce, deadline);

        vm.prank(alice);
        vm.expectRevert("invalid signature");
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
    }

    function test_mint_revertsWhenSignerRoleIsRevoked() public {
        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 1, nonce, deadline);

        bytes32 role = pass.SIGNER_ROLE();
        vm.prank(admin);
        pass.revokeRole(role, signer);

        vm.prank(alice);
        vm.expectRevert("invalid signature");
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
    }

    function test_mint_newSignerWorksAfterGrant() public {
        (address newSigner, uint256 newPk) = makeAddrAndKey("newSigner");
        bytes32 role = pass.SIGNER_ROLE();
        vm.prank(admin);
        pass.grantRole(role, newSigner);

        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(newPk, address(pass), alice, GOLD, 1, nonce, deadline);
        vm.prank(alice);
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
        assertEq(pass.balanceOf(alice, GOLD), 1);
    }

    function test_mint_everySignedFieldIsBound() public {
        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 1, nonce, deadline);

        vm.startPrank(alice);
        vm.expectRevert("invalid signature"); // different tier
        pass.mintWithSignature(SILVER, 1, nonce, deadline, sig);
        vm.expectRevert("invalid signature"); // different amount
        pass.mintWithSignature(GOLD, 2, nonce, deadline, sig);
        vm.expectRevert("invalid signature"); // different nonce
        pass.mintWithSignature(GOLD, 1, nonce + 1, deadline, sig);
        vm.stopPrank();
    }

    function test_mint_signatureIsBoundToTheCaller() public {
        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 1, nonce, deadline);

        vm.prank(bob); // bob steals alice's voucher
        vm.expectRevert("invalid signature");
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
    }

    function test_mint_signatureIsBoundToThisContract() public {
        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(harness), alice, GOLD, 1, nonce, deadline); // meant for another pass

        vm.prank(alice);
        vm.expectRevert("invalid signature");
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
    }

    function test_mint_signatureIsBoundToTheChain() public {
        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 1, nonce, deadline);

        vm.chainId(block.chainid + 1); // the same voucher shown on another chain
        vm.prank(alice);
        vm.expectRevert("invalid signature");
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
    }

    function test_mint_malformedSignatureReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        pass.mintWithSignature(GOLD, 1, 1, _deadline(), hex"1234");
    }

    // supply cap

    function test_cap_uncappedTierMintsFreely() public {
        _mintFor(alice, GOLD, 1_000_000);
        assertEq(pass.balanceOf(alice, GOLD), 1_000_000);
    }

    function test_cap_mintUpToTheCapIsAllowed() public {
        vm.prank(admin);
        pass.setMaxSupply(GOLD, 10);

        _mintFor(alice, GOLD, 6);
        _mintFor(bob, GOLD, 4);
        assertEq(pass.totalMinted(GOLD), 10);
    }

    function test_cap_mintBeyondTheCapReverts() public {
        vm.prank(admin);
        pass.setMaxSupply(GOLD, 10);
        _mintFor(alice, GOLD, 6);

        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), bob, GOLD, 5, nonce, deadline);
        vm.prank(bob);
        vm.expectRevert("exceeds tier supply");
        pass.mintWithSignature(GOLD, 5, nonce, deadline, sig);

        assertFalse(pass.usedNonces(nonce)); // the failed mint did not burn the nonce
        assertEq(pass.totalMinted(GOLD), 6);
    }

    function test_cap_capsAreIndependentPerTier() public {
        vm.prank(admin);
        pass.setMaxSupply(GOLD, 1);

        _mintFor(alice, GOLD, 1);
        _mintFor(alice, SILVER, 50); // silver has no cap
        assertEq(pass.totalMinted(SILVER), 50);
    }

    function test_cap_raisingTheCapAllowsMoreMinting() public {
        vm.startPrank(admin);
        pass.setMaxSupply(GOLD, 1);
        vm.stopPrank();
        _mintFor(alice, GOLD, 1);

        vm.prank(admin);
        pass.setMaxSupply(GOLD, 2);
        _mintFor(bob, GOLD, 1);
        assertEq(pass.totalMinted(GOLD), 2);
    }

    // the patch: totalMinted and the cap live in _update

    function test_update_aNewMintPathIsCountedAutomatically() public {
        harness.unsafeMint(alice, GOLD, 5); // no signature, no cap check in this path

        assertEq(harness.balanceOf(alice, GOLD), 5);
        assertEq(harness.totalMinted(GOLD), 5); // _update counted it anyway
    }

    function test_update_aNewMintPathStillRespectsTheCap() public {
        vm.prank(admin);
        harness.setMaxSupply(GOLD, 10);
        harness.unsafeMint(alice, GOLD, 6);

        vm.expectRevert("tier supply exceeded");
        harness.unsafeMint(alice, GOLD, 5);

        assertEq(harness.totalMinted(GOLD), 6);
        assertEq(harness.balanceOf(alice, GOLD), 6);
    }

    function test_update_batchMintIsCountedAndCappedPerTier() public {
        vm.prank(admin);
        harness.setMaxSupply(SILVER, 3);

        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = GOLD;
        ids[1] = SILVER;
        amounts[0] = 5;
        amounts[1] = 3;
        harness.unsafeMintBatch(alice, ids, amounts);
        assertEq(harness.totalMinted(GOLD), 5);
        assertEq(harness.totalMinted(SILVER), 3);

        vm.expectRevert("tier supply exceeded"); // silver is now full, so the whole batch fails
        harness.unsafeMintBatch(alice, ids, amounts);
        assertEq(harness.totalMinted(GOLD), 5); // gold was not partly counted
    }

    function test_update_transfersDoNotChangeSupply() public {
        _mintFor(alice, GOLD, 5);

        vm.prank(alice);
        pass.safeTransferFrom(alice, bob, GOLD, 5, "");

        assertEq(pass.totalMinted(GOLD), 5);
        assertEq(pass.balanceOf(bob, GOLD), 5);
    }

    function test_update_burningDoesNotFreeUpSupply() public {
        vm.prank(admin);
        harness.setMaxSupply(GOLD, 5);
        harness.unsafeMint(alice, GOLD, 5);

        harness.unsafeBurn(alice, GOLD, 5);
        assertEq(harness.totalMinted(GOLD), 5); // totalMinted is a lifetime count

        vm.expectRevert("tier supply exceeded");
        harness.unsafeMint(alice, GOLD, 1);
    }

    // the receiver hook

    function test_receiver_contractWithoutHookCannotMint() public {
        NoReceiver receiver = new NoReceiver();
        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), address(receiver), GOLD, 1, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidReceiver.selector, address(receiver)));
        receiver.mint(pass, GOLD, 1, nonce, deadline, sig);
    }

    function test_receiver_hookCannotReplayTheSignature() public {
        ReentrantReceiver attacker = new ReentrantReceiver();
        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), address(attacker), GOLD, 1, nonce, deadline);

        attacker.attack(pass, GOLD, 1, nonce, deadline, sig);

        assertEq(attacker.lastError(), abi.encodeWithSignature("Error(string)", "nonce already used"));
        assertEq(pass.balanceOf(address(attacker), GOLD), 1); // minted once only
        assertEq(pass.totalMinted(GOLD), 1);
    }

    // fuzz tests

    function testFuzz_mintUpToCap(uint256 cap, uint256 amount) public {
        cap = bound(cap, 1, 1_000_000);
        amount = bound(amount, 1, cap);
        vm.prank(admin);
        pass.setMaxSupply(GOLD, cap);

        _mintFor(alice, GOLD, amount);

        assertEq(pass.balanceOf(alice, GOLD), amount);
        assertEq(pass.totalMinted(GOLD), amount);
    }

    function testFuzz_mintOverCapReverts(uint256 cap, uint256 extra) public {
        cap = bound(cap, 1, 1_000_000);
        extra = bound(extra, 1, 1_000_000);
        vm.prank(admin);
        pass.setMaxSupply(GOLD, cap);

        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, cap + extra, nonce, deadline);
        vm.prank(alice);
        vm.expectRevert("exceeds tier supply");
        pass.mintWithSignature(GOLD, cap + extra, nonce, deadline, sig);
    }

    function testFuzz_signatureOnlyWorksForTheSignedAmount(uint256 signedAmount, uint256 usedAmount) public {
        signedAmount = bound(signedAmount, 1, 1_000_000);
        usedAmount = bound(usedAmount, 1, 1_000_000);
        vm.assume(signedAmount != usedAmount);

        uint256 nonce = nextNonce++;
        uint256 deadline = _deadline();
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, signedAmount, nonce, deadline);

        vm.prank(alice);
        vm.expectRevert("invalid signature");
        pass.mintWithSignature(GOLD, usedAmount, nonce, deadline, sig);
    }

    function testFuzz_expiredSignaturesNeverWork(uint256 lifetime, uint256 lateBy) public {
        lifetime = bound(lifetime, 1, 30 days);
        lateBy = bound(lateBy, 1, 365 days);
        uint256 nonce = nextNonce++;
        uint256 deadline = block.timestamp + lifetime;
        bytes memory sig = _sign(signerPk, address(pass), alice, GOLD, 1, nonce, deadline);

        vm.warp(deadline + lateBy);
        vm.prank(alice);
        vm.expectRevert("signature expired");
        pass.mintWithSignature(GOLD, 1, nonce, deadline, sig);
    }

    // invariants (run against the handler's own pass)

    function invariant_totalMintedEqualsSumOfBalances() public view {
        for (uint256 t = 0; t < handler.TIERS(); t++) {
            assertEq(handler.pass().totalMinted(t), handler.sumOfBalances(t));
        }
    }

    function invariant_totalMintedNeverExceedsACap() public view {
        for (uint256 t = 0; t < handler.TIERS(); t++) {
            uint256 cap = handler.pass().maxSupply(t);
            if (cap != 0) {
                assertLe(handler.pass().totalMinted(t), cap);
            }
        }
    }
}
