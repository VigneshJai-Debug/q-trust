// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {ProxyDeploy} from "./helpers/ProxyDeploy.sol";
import "../src/RevocationAnchor.sol";
import "../src/lib/StringBounds.sol";

contract RevocationAnchorTest is Test {
    RevocationAnchor public anchor;

    address admin = address(0xA001);
    address nonIssuer = address(0xDEADBEEF);

    uint256 issuerKey1 = 0xA11CE;
    uint256 issuerKey2 = 0xB0B;
    address issuer1;
    address issuer2;
    bytes32 private constant _ROOT_UPDATE_TYPEHASH =
        keccak256("RevocationRootUpdate(address issuer,bytes32 newRoot,uint256 nonce)");

    function _signRootUpdate(
        address signer,
        uint256 sk,
        address issuer,
        bytes32 newRoot,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(_ROOT_UPDATE_TYPEHASH, issuer, newRoot, nonce)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", anchor.domainSeparator(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function setUp() public {
        issuer1 = vm.addr(issuerKey1);
        issuer2 = vm.addr(issuerKey2);
        anchor = ProxyDeploy.revocation();
        anchor.registerIssuer(issuer1, "did:web:trailofbits.com");
        anchor.registerIssuer(issuer2, "did:web:digicert.com");
    }

    // ======== Registration ========

    function test_RegisterIssuer() public {
        RevocationAnchor.IssuerInfo memory info = anchor.getIssuer(issuer1);
        assertEq(info.issuerDid, "did:web:trailofbits.com");
        assertTrue(info.active);
    }

    function test_IssuerCount() public {
        assertEq(anchor.issuerCount(), 2);
    }

    function test_GetAllIssuers() public {
        address[] memory issuers = anchor.getAllIssuers();
        assertEq(issuers.length, 2);
        assertEq(issuers[0], issuer1);
        assertEq(issuers[1], issuer2);
    }

    // ======== Root Updates ========

    function test_UpdateRoot_Direct() public {
        bytes32 root = keccak256("merkle-root-1");
        bytes32 prev = anchor.updateRoot(issuer1, root);

        assertEq(prev, bytes32(0), "previous root should be zero");
        assertEq(anchor.getRevocationRoot(issuer1), root);
    }

    function test_UpdateRoot_PreviousRoot() public {
        bytes32 root1 = keccak256("merkle-root-1");
        bytes32 root2 = keccak256("merkle-root-2");

        anchor.updateRoot(issuer1, root1);
        bytes32 prev = anchor.updateRoot(issuer1, root2);

        assertEq(prev, root1, "previous root should be root1");
        assertEq(anchor.getRevocationRoot(issuer1), root2);
    }

    function test_UpdateRoot_EIP712() public {
        bytes32 root = keccak256("merkle-root-eip712");
        bytes memory sig = _signRootUpdate(issuer1, issuerKey1, issuer1, root, 0);
        bytes32 prev = anchor.updateRootSigned(issuer1, root, 0, sig);

        assertEq(prev, bytes32(0));
        assertEq(anchor.getRevocationRoot(issuer1), root);
    }

    function test_UpdateRoot_EIP712_NonceIncrement() public {
        bytes32 root1 = keccak256("root-1");
        bytes32 root2 = keccak256("root-2");

        bytes memory sig1 = _signRootUpdate(issuer1, issuerKey1, issuer1, root1, 0);
        anchor.updateRootSigned(issuer1, root1, 0, sig1);

        bytes memory sig2 = _signRootUpdate(issuer1, issuerKey1, issuer1, root2, 1);
        anchor.updateRootSigned(issuer1, root2, 1, sig2);

        assertEq(anchor.getRevocationRoot(issuer1), root2);
        assertEq(anchor.nonces(issuer1), 2);
    }

    // ======== Access Control ========

    function test_UpdateRoot_Revert_NotIssuer() public {
        vm.expectRevert(abi.encodeWithSelector(RevocationAnchor.IssuerNotRegistered.selector, nonIssuer));
        anchor.updateRoot(nonIssuer, keccak256("root"));
    }

    function test_UpdateRoot_Revert_EmptyRoot() public {
        vm.expectRevert(abi.encodeWithSelector(RevocationAnchor.EmptyRoot.selector));
        anchor.updateRoot(issuer1, bytes32(0));
    }

    function test_UpdateRoot_Revert_EIP712_WrongSigner() public {
        bytes32 root = keccak256("root");
        bytes memory sig = _signRootUpdate(nonIssuer, 0xBAD, issuer1, root, 0);
        vm.expectRevert(abi.encodeWithSelector(RevocationAnchor.InvalidSignature.selector));
        anchor.updateRootSigned(issuer1, root, 0, sig);
    }

    function test_UpdateRoot_Revert_EIP712_WrongNonce() public {
        bytes32 root = keccak256("root");
        bytes memory sig = _signRootUpdate(issuer1, issuerKey1, issuer1, root, 5);
        vm.expectRevert(abi.encodeWithSelector(RevocationAnchor.InvalidNonce.selector, issuer1, 5, 0));
        anchor.updateRootSigned(issuer1, root, 5, sig);
    }

    // ======== Deactivation ========

    function test_DeactivateIssuer() public {
        anchor.deactivateIssuer(issuer1);
        assertFalse(anchor.isIssuerActive(issuer1));
    }

    function test_RevertWhen_DeactivatedIssuerUpdatesRoot() public {
        // Regression test (audit M-2): a deactivated issuer must not be able
        // to anchor new revocation roots on either path.
        anchor.deactivateIssuer(issuer1);

        vm.expectRevert(abi.encodeWithSelector(RevocationAnchor.IssuerInactive.selector, issuer1));
        anchor.updateRoot(issuer1, keccak256("root-after-deactivation"));
    }

    function test_RevertWhen_DeactivatedIssuerUpdatesRootSigned() public {
        // Same guard must hold on the EIP-712 gasless path.
        anchor.deactivateIssuer(issuer1);
        bytes32 root = keccak256("signed-root-after-deactivation");
        bytes memory sig = _signRootUpdate(issuer1, issuerKey1, issuer1, root, 0);

        vm.prank(makeAddr("relayer"));
        vm.expectRevert(abi.encodeWithSelector(RevocationAnchor.IssuerInactive.selector, issuer1));
        anchor.updateRootSigned(issuer1, root, 0, sig);
    }

    // ======== Pausable ========

    function test_Pause_Unpause() public {
        anchor.pause();
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        anchor.updateRoot(issuer1, keccak256("root"));

        anchor.unpause();
        anchor.updateRoot(issuer1, keccak256("root"));
        assertTrue(true);
    }

    // ======== View Functions ========

    function test_IsIssuerActive() public {
        assertTrue(anchor.isIssuerActive(issuer1));
        anchor.deactivateIssuer(issuer1);
        assertFalse(anchor.isIssuerActive(issuer1));
    }

    function test_GetIssuer_Revert_NotRegistered() public {
        vm.expectRevert(abi.encodeWithSelector(RevocationAnchor.IssuerNotRegistered.selector, nonIssuer));
        anchor.getIssuer(nonIssuer);
    }

    // ======== TD8/L1 regression ========

    function test_RevertWhen_IssuerDidTooLong() public {
        string memory longDid = string(new bytes(129));
        vm.expectRevert(
            abi.encodeWithSelector(StringBounds.StringTooLong.selector, 129, 128)
        );
        anchor.registerIssuer(address(0xFACE), longDid);
    }

    function test_DomainSeparator_ChainFork_SignedStillVerifies() public {
        bytes32 sepBefore = anchor.domainSeparator();

        // Simulate a chain fork: the separator must re-derive for chain 999.
        vm.chainId(999);
        assertFalse(anchor.domainSeparator() == sepBefore, "separator must re-derive on new chainid");

        // A signature produced against the forked-chain separator must verify.
        bytes32 root = keccak256("fork-root");
        bytes memory sig = _signRootUpdate(issuer1, issuerKey1, issuer1, root, 0);
        bytes32 prev = anchor.updateRootSigned(issuer1, root, 0, sig);

        assertEq(prev, bytes32(0));
        assertEq(anchor.getRevocationRoot(issuer1), root);
    }
}
