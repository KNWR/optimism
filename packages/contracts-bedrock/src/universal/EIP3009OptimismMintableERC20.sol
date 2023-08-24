// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IEIP3009 } from "./IEIP3009.sol";
import {OptimismMintableERC20} from "./OptimismMintableERC20.sol";

/**
 * @title EIP3009OptimismMintableERC20
 * @notice Provide internal implementation for gas-abstracted transfers on Optimism
 * @dev Contracts that inherit from this must wrap these with publicly
 * accessible functions, optionally adding modifiers where necessary
 */
contract EIP3009OptimismMintableERC20 is IEIP3009, EIP712, OptimismMintableERC20{
    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32
        public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = 0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    // keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32
        public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = 0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;

    // keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
    bytes32
        public constant CANCEL_AUTHORIZATION_TYPEHASH = 0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

    /**
     * @dev authorizer address => nonce => bool (true if nonce is used)
     */
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    /**
     * @notice Emitted when an authorization is canceled
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     */
    event AuthorizationCanceled(
        address indexed authorizer,
        bytes32 indexed nonce
    );

    /// @notice Decimal user representation.
    uint8 internal immutable _DECIMALS;

    /// @notice Constructor method
    /// @param _bridge      Address of the L2 standard bridge.
    /// @param _remoteToken Address of the corresponding L1 token.
    /// @param _name        ERC20 name.
    /// @param _symbol      ERC20 symbol.
    /// @param _decimals    User decimal place representation.
    constructor(
        address _bridge,
        address _remoteToken,
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    )
        OptimismMintableERC20(_bridge, _remoteToken, _name, _symbol)
        EIP712(_name, "1")
    {
        _DECIMALS = _decimals;
    }

    /**
     * @notice Returns the state of an authorization
     * @dev Nonces are randomly generated 32-byte data unique to the
     * authorizer's address
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @return True if the nonce is used
     */
    function authorizationState(address authorizer, bytes32 nonce)
        external
        view
        returns (bool)
    {
        return _authorizationStates[authorizer][nonce];
    }

    /**
     * @notice Execute a transfer with a signed authorization
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        _requireValidAuthorization(from, nonce, validAfter, validBefore);

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
            from,
            to,
            value,
            validAfter,
            validBefore,
            nonce
       )));

        require(
            ECDSA.recover(digest, v, r, s) == from,
            "EIP3009OptimismMintableERC20: invalid signature"
        );

        _markAuthorizationAsUsed(from, nonce);
        _transfer(from, to, value);
    }

    /**
     * @notice Receive a transfer with a signed authorization from the payer
     * @dev This has an additional check to ensure that the payee's address
     * matches the caller of this function to prevent front-running attacks.
     * @param from          Payer's address (Authorizer)
     * @param to            Payee's address
     * @param value         Amount to be transferred
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     * @param nonce         Unique nonce
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(to == msg.sender, "EIP3009OptimismMintableERC20: caller must be the payee");
        _requireValidAuthorization(from, nonce, validAfter, validBefore);

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
            from,
            to,
            value,
            validAfter,
            validBefore,
            nonce
       )));

        require(
            ECDSA.recover(digest, v, r, s) == from,
            "EIP3009OptimismMintableERC20: invalid signature"
        );

        _markAuthorizationAsUsed(from, nonce);
        _transfer(from, to, value);
    }

    /**
     * @notice Attempt to cancel an authorization
     * @dev Emits an {AuthorizationCanceled} event.
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        _requireUnusedAuthorization(authorizer, nonce);

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            CANCEL_AUTHORIZATION_TYPEHASH,
            authorizer,
            nonce
       )));

        require(
            ECDSA.recover(digest, v, r, s) == authorizer,
            "EIP3009OptimismMintableERC20: invalid signature"
        );

        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    /**
     * @notice Check that an authorization is unused
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     */
    function _requireUnusedAuthorization(address authorizer, bytes32 nonce)
        private
        view
    {
        require(
            !_authorizationStates[authorizer][nonce],
            "EIP3009OptimismMintableERC20: authorization is used or canceled"
        );
    }

    /**
     * @notice Check that authorization is valid
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     */
    function _requireValidAuthorization(
        address authorizer,
        bytes32 nonce,
        uint256 validAfter,
        uint256 validBefore
    ) private view {
        require(
            block.timestamp > validAfter,
            "EIP3009OptimismMintableERC20: authorization is not yet valid"
        );
        require(block.timestamp < validBefore, "EIP3009OptimismMintableERC20: authorization is expired");
        _requireUnusedAuthorization(authorizer, nonce);
    }

    /**
     * @notice Mark an authorization as used
     * @dev Emits an {AuthorizationUsed} event.
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     */
    function _markAuthorizationAsUsed(address authorizer, bytes32 nonce)
        private
    {
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }

}