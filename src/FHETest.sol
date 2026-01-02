// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {MockNetwork} from "./MockNetwork.sol";
import {ACL} from "./ACL.sol";
import "@luxfi/contracts/fhe/FHE.sol";
import {MockZkVerifier} from "./MockZkVerifier.sol";
import {MockZkVerifierSigner} from "./MockZkVerifierSigner.sol";
import {ZK_VERIFIER_ADDRESS, ZK_VERIFIER_SIGNER_ADDRESS} from "./addresses/ZkVerifierAddress.sol";
import {TASK_MANAGER_ADDRESS} from "./addresses/TaskManagerAddress.sol";
import {FHE_NETWORK_ADDRESS} from "./addresses/FHENetworkAddress.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Permission, PermissionUtils} from "./Permissioned.sol";
import {MockQueryDecrypter} from "./MockQueryDecrypter.sol";
import {QUERY_DECRYPTER_ADDRESS} from "./addresses/QueryDecrypterAddress.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SIGNER_ADDRESS} from "./MockLuxFHE.sol";

contract FHETest is Test {
    MockNetwork public fheNetwork;
    MockZkVerifier public zkVerifier;
    MockZkVerifierSigner public zkVerifierSigner;
    ACL public acl;
    MockQueryDecrypter public queryDecrypter;

    address public ACL_ADDRESS = 0xa6Ea4b5291d044D93b73b3CFf3109A1128663E8B;

    bool private _log;

    address public constant NETWORK_ADMIN = address(128);

    constructor(bool log) {
        _log = log;
        etchLuxFHEMocks();
    }

    // SETUP

    function etchLuxFHEMocks() internal {
        // Override chain id (uncomment to enable)
        // vm.chainId(421614); // Arb Sepolia
        // vm.chainId(31337); // Anvil
        vm.chainId(420105); // Localluxfhe host 1

        // FHE NETWORK
        deployCodeTo("MockNetwork.sol:MockNetwork", FHE_NETWORK_ADDRESS);
        fheNetwork = MockNetwork(FHE_NETWORK_ADDRESS);
        fheNetwork.initialize(NETWORK_ADMIN);
        vm.label(address(fheNetwork), "MockNetwork");

        vm.startPrank(NETWORK_ADMIN);
        fheNetwork.setSecurityZoneMin(0);
        fheNetwork.setSecurityZoneMax(1);
        fheNetwork.setVerifierSigner(SIGNER_ADDRESS);
        vm.stopPrank();

        // ACL

        // Deploy implementation
        ACL aclImplementation = new ACL();

        // Deploy proxy with implementation
        bytes memory initData = abi.encodeWithSelector(
            ACL.initialize.selector,
            NETWORK_ADMIN
        );
        deployCodeTo(
            "ERC1967Proxy.sol:ERC1967Proxy",
            abi.encode(address(aclImplementation), initData),
            ACL_ADDRESS
        );
        acl = ACL(ACL_ADDRESS);
        vm.label(address(acl), "ACL");

        vm.prank(NETWORK_ADMIN);
        fheNetwork.setACLContract(address(acl));

        // ZK VERIFIER

        deployCodeTo("MockZkVerifier.sol:MockZkVerifier", ZK_VERIFIER_ADDRESS);
        zkVerifier = MockZkVerifier(ZK_VERIFIER_ADDRESS);
        vm.label(address(zkVerifier), "MockZkVerifier");

        deployCodeTo(
            "MockZkVerifierSigner.sol:MockZkVerifierSigner",
            ZK_VERIFIER_SIGNER_ADDRESS
        );
        zkVerifierSigner = MockZkVerifierSigner(ZK_VERIFIER_SIGNER_ADDRESS);
        vm.label(address(zkVerifierSigner), "MockZkVerifierSigner");

        // QUERY DECRYPTER

        deployCodeTo(
            "MockQueryDecrypter.sol:MockQueryDecrypter",
            QUERY_DECRYPTER_ADDRESS
        );
        queryDecrypter = MockQueryDecrypter(QUERY_DECRYPTER_ADDRESS);
        vm.label(address(queryDecrypter), "MockQueryDecrypter");
        queryDecrypter.initialize(TASK_MANAGER_ADDRESS, address(acl));

        // SET LOG OPS

        fheNetwork.setLogOps(_log);
    }

    // EXPOSED FUNCTIONS

    /**
     * @notice              Returns the value of a given encrypted value from the mocked task manager.
     * @param ctHash        Hash of the encrypted value.
     * @return              Value of the encrypted value.
     */
    function mockStorage(uint256 ctHash) public view returns (uint256) {
        return fheNetwork.mockStorage(ctHash);
    }

    /**
     * @notice              Returns whether a given encrypted value is in the mocked task manager.
     * @param ctHash        Hash of the encrypted value.
     * @return              Whether the encrypted value is in the mocked task manager.
     */
    function inMockStorage(uint256 ctHash) public view returns (bool) {
        return fheNetwork.inMockStorage(ctHash);
    }

    // ASSERTIONS

    // Hash

    /**
     * @notice              Asserts that the value of a given encrypted value is equal to the expected value.
     * @param ctHash        Hash of the encrypted value.
     * @param value         Expected value.
     */
    function assertHashValue(uint256 ctHash, uint256 value) public view {
        assertEq(fheNetwork.inMockStorage(ctHash), true);
        assertEq(fheNetwork.mockStorage(ctHash), value);
    }
    function assertHashValue(
        uint256 ctHash,
        uint256 value,
        string memory message
    ) public view {
        assertEq(fheNetwork.inMockStorage(ctHash), true, message);
        assertEq(fheNetwork.mockStorage(ctHash), value, message);
    }

    // Encrypted types (no message)

    function assertHashValue(ebool eValue, bool value) public view {
        assertHashValue(ebool.unwrap(eValue), value ? 1 : 0);
    }
    function assertHashValue(euint8 eValue, uint8 value) public view {
        assertHashValue(euint8.unwrap(eValue), value);
    }
    function assertHashValue(euint16 eValue, uint16 value) public view {
        assertHashValue(euint16.unwrap(eValue), value);
    }
    function assertHashValue(euint32 eValue, uint32 value) public view {
        assertHashValue(euint32.unwrap(eValue), value);
    }
    function assertHashValue(euint64 eValue, uint64 value) public view {
        assertHashValue(euint64.unwrap(eValue), value);
    }
    function assertHashValue(euint128 eValue, uint128 value) public view {
        assertHashValue(euint128.unwrap(eValue), value);
    }
    function assertHashValue(eaddress eValue, address value) public view {
        assertHashValue(eaddress.unwrap(eValue), uint256(uint160(value)));
    }

    // Encrypted types (with message)

    function assertHashValue(
        ebool eValue,
        bool value,
        string memory message
    ) public view {
        assertHashValue(ebool.unwrap(eValue), value ? 1 : 0, message);
    }
    function assertHashValue(
        euint8 eValue,
        uint8 value,
        string memory message
    ) public view {
        assertHashValue(euint8.unwrap(eValue), value, message);
    }
    function assertHashValue(
        euint16 eValue,
        uint16 value,
        string memory message
    ) public view {
        assertHashValue(euint16.unwrap(eValue), value, message);
    }
    function assertHashValue(
        euint32 eValue,
        uint32 value,
        string memory message
    ) public view {
        assertHashValue(euint32.unwrap(eValue), value, message);
    }
    function assertHashValue(
        euint64 eValue,
        uint64 value,
        string memory message
    ) public view {
        assertHashValue(euint64.unwrap(eValue), value, message);
    }
    function assertHashValue(
        euint128 eValue,
        uint128 value,
        string memory message
    ) public view {
        assertHashValue(euint128.unwrap(eValue), value, message);
    }
    function assertHashValue(
        eaddress eValue,
        address value,
        string memory message
    ) public view {
        assertHashValue(
            eaddress.unwrap(eValue),
            uint256(uint160(value)),
            message
        );
    }

    // UTILS

    // struct EncryptedInput {
    // uint256 ctHash;
    // uint8 securityZone;
    // uint8 utype;
    // bytes signature;
    // }

    function createEncryptedInput(
        uint8 utype,
        uint256 value,
        uint8 securityZone,
        address sender
    ) internal returns (EncryptedInput memory input) {
        // Create input
        input = zkVerifier.zkVerify(
            value,
            utype,
            sender,
            securityZone,
            block.chainid
        );

        input = zkVerifierSigner.zkVerifySign(input, sender);
    }

    // Derived functions that use the generic create

    /**
     * @notice              Creates an Ebool to be used as FHE input. Value is stored in MockLuxFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              Ebool.
     */
    function createEbool(
        bool value,
        uint8 securityZone,
        address sender
    ) public returns (Ebool memory) {
        return
            abi.decode(
                abi.encode(
                    createEncryptedInput(
                        Utils.EBOOL_TFHE,
                        value ? 1 : 0,
                        securityZone,
                        sender
                    )
                ),
                (Ebool)
            );
    }

    /**
     * @notice              Creates an Euint8 to be used as FHE input. Value is stored in MockLuxFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              Euint8.
     */
    function createEuint8(
        uint8 value,
        uint8 securityZone,
        address sender
    ) public returns (Euint8 memory) {
        return
            abi.decode(
                abi.encode(
                    createEncryptedInput(
                        Utils.EUINT8_TFHE,
                        value,
                        securityZone,
                        sender
                    )
                ),
                (Euint8)
            );
    }

    /**
     * @notice              Creates an Euint16 to be used as FHE input. Value is stored in MockLuxFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              Euint16.
     */
    function createEuint16(
        uint16 value,
        uint8 securityZone,
        address sender
    ) public returns (Euint16 memory) {
        return
            abi.decode(
                abi.encode(
                    createEncryptedInput(
                        Utils.EUINT16_TFHE,
                        value,
                        securityZone,
                        sender
                    )
                ),
                (Euint16)
            );
    }

    /**
     * @notice              Creates an Euint32 to be used as FHE input. Value is stored in MockLuxFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              Euint32.
     */
    function createEuint32(
        uint32 value,
        uint8 securityZone,
        address sender
    ) public returns (Euint32 memory) {
        return
            abi.decode(
                abi.encode(
                    createEncryptedInput(
                        Utils.EUINT32_TFHE,
                        value,
                        securityZone,
                        sender
                    )
                ),
                (Euint32)
            );
    }

    /**
     * @notice              Creates an Euint64 to be used as FHE input. Value is stored in MockLuxFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              Euint64.
     */
    function createEuint64(
        uint64 value,
        uint8 securityZone,
        address sender
    ) public returns (Euint64 memory) {
        return
            abi.decode(
                abi.encode(
                    createEncryptedInput(
                        Utils.EUINT64_TFHE,
                        value,
                        securityZone,
                        sender
                    )
                ),
                (Euint64)
            );
    }

    /**
     * @notice              Creates an Euint128 to be used as FHE input. Value is stored in MockLuxFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              Euint128.
     */
    function createEuint128(
        uint128 value,
        uint8 securityZone,
        address sender
    ) public returns (Euint128 memory) {
        return
            abi.decode(
                abi.encode(
                    createEncryptedInput(
                        Utils.EUINT128_TFHE,
                        value,
                        securityZone,
                        sender
                    )
                ),
                (Euint128)
            );
    }

    /**
     * @notice              Creates an Euint256 to be used as FHE input. Value is stored in MockLuxFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              Euint256.
     */
    function createEuint256(
        uint256 value,
        uint8 securityZone,
        address sender
    ) public returns (Euint256 memory) {
        return
            abi.decode(
                abi.encode(
                    createEncryptedInput(
                        Utils.EUINT256_TFHE,
                        value,
                        securityZone,
                        sender
                    )
                ),
                (Euint256)
            );
    }

    /**
     * @notice              Creates an Eaddress to be used as FHE input. Value is stored in MockLuxFHE contract, hash is a pointer to that value.
     * @param value         Value to encrypt.
     * @param securityZone  Security zone of the encrypted value.
     * @return              Eaddress.
     */
    function createEaddress(
        address value,
        uint8 securityZone,
        address sender
    ) public returns (Eaddress memory) {
        return
            abi.decode(
                abi.encode(
                    createEncryptedInput(
                        Utils.EADDRESS_TFHE,
                        uint256(uint160(value)),
                        securityZone,
                        sender
                    )
                ),
                (Eaddress)
            );
    }

    // Overloads with default securityZone=0 for backward compatibility

    function createEbool(
        bool value,
        address sender
    ) public returns (Ebool memory) {
        return createEbool(value, 0, sender);
    }

    function createEuint8(
        uint8 value,
        address sender
    ) public returns (Euint8 memory) {
        return createEuint8(value, 0, sender);
    }

    function createEuint16(
        uint16 value,
        address sender
    ) public returns (Euint16 memory) {
        return createEuint16(value, 0, sender);
    }

    function createEuint32(
        uint32 value,
        address sender
    ) public returns (Euint32 memory) {
        return createEuint32(value, 0, sender);
    }

    function createEuint64(
        uint64 value,
        address sender
    ) public returns (Euint64 memory) {
        return createEuint64(value, 0, sender);
    }

    function createEuint128(
        uint128 value,
        address sender
    ) public returns (Euint128 memory) {
        return createEuint128(value, 0, sender);
    }

    function createEuint256(
        uint256 value,
        address sender
    ) public returns (Euint256 memory) {
        return createEuint256(value, 0, sender);
    }

    function createEaddress(
        address value,
        address sender
    ) public returns (Eaddress memory) {
        return createEaddress(value, 0, sender);
    }

    // PERMISSIONS

    bytes32 private constant PERMISSION_TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    function permissionDomainSeparator() internal view returns (bytes32) {
        string memory name;
        string memory version;
        uint256 chainId;
        address verifyingContract;

        (, name, version, chainId, verifyingContract, , ) = acl.eip712Domain();

        return
            keccak256(
                abi.encode(
                    PERMISSION_TYPE_HASH,
                    keccak256(bytes(name)),
                    keccak256(bytes(version)),
                    chainId,
                    verifyingContract
                )
            );
    }

    function permissionHashTypedDataV4(
        bytes32 structHash
    ) public view returns (bytes32) {
        return
            MessageHashUtils.toTypedDataHash(
                permissionDomainSeparator(),
                structHash
            );
    }

    function signPermission(
        bytes32 structHash,
        uint256 pkey
    ) public pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkey, structHash);
        return abi.encodePacked(r, s, v); // note the order here is different from line above.
    }

    function signPermissionSelf(
        Permission memory permission,
        uint256 pkey
    ) public view returns (Permission memory signedPermission) {
        signedPermission = permission;

        bytes32 permissionHash = PermissionUtils.issuerSelfHash(permission);
        bytes32 structHash = permissionHashTypedDataV4(permissionHash);

        signedPermission.issuerSignature = signPermission(structHash, pkey);
    }

    function signPermissionShared(
        Permission memory permission,
        uint256 pkey
    ) public view returns (Permission memory signedPermission) {
        signedPermission = permission;
        bytes32 permissionHash = PermissionUtils.issuerSharedHash(permission);
        bytes32 structHash = permissionHashTypedDataV4(permissionHash);

        signedPermission.issuerSignature = signPermission(structHash, pkey);
    }

    function signPermissionRecipient(
        Permission memory permission,
        uint256 pkey
    ) public view returns (Permission memory signedPermission) {
        signedPermission = permission;

        bytes32 permissionHash = PermissionUtils.recipientHash(permission);
        bytes32 structHash = permissionHashTypedDataV4(permissionHash);

        signedPermission.recipientSignature = signPermission(structHash, pkey);
    }

    function createBasePermission()
        public
        pure
        returns (Permission memory permission)
    {
        permission = Permission({
            issuer: address(0),
            expiration: 1000000000000,
            recipient: address(0),
            validatorId: 0,
            validatorContract: address(0),
            sealingKey: bytes32(0),
            issuerSignature: new bytes(0),
            recipientSignature: new bytes(0)
        });
    }

    function createPermissionSelf(
        address issuer
    ) public pure returns (Permission memory permission) {
        permission = createBasePermission();
        permission.issuer = issuer;
    }

    function createPermissionShared(
        address issuer,
        address recipient
    ) public pure returns (Permission memory permission) {
        permission = createBasePermission();
        permission.issuer = issuer;
        permission.recipient = recipient;
    }

    function createSealingKey(uint256 seed) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(seed));
    }

    function queryDecrypt(
        uint256 ctHash,
        uint256 hostChainId,
        Permission memory permission
    ) public view returns (bool, string memory error, uint256) {
        return queryDecrypter.queryDecrypt(ctHash, hostChainId, permission);
    }

    function querySealOutput(
        uint256 ctHash,
        uint256 hostChainId,
        Permission memory permission
    ) public view returns (bool, string memory error, bytes32) {
        return queryDecrypter.querySealOutput(ctHash, hostChainId, permission);
    }

    function unseal(bytes32 hashed, bytes32 key) public view returns (uint256) {
        return queryDecrypter.unseal(hashed, key);
    }
}
