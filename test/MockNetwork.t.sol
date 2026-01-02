// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {FHETest} from "../src/FHETest.sol";
import "@luxfi/contracts/fhe/FHE.sol";

contract SimpleDecrypter {
    function decrypt(Euint8 memory Euint8Value) public {
        euint8 euint8Value = FHE.asEuint8(Euint8Value);
        FHE.decrypt(euint8Value);
    }

    function decrypt(euint8 euint8Value) public {
        FHE.decrypt(euint8Value);
    }

    function getDecryptResult(uint256 ctHash) public view returns (uint256) {
        return FHE.getDecryptResult(ctHash);
    }
}

contract MockNetworkTests is Test {
    FHETest FHT;
    SimpleDecrypter simpleDecrypter;
    SimpleDecrypter thiefDecrypter;

    function setUp() public {
        FHT = new FHETest(false);

        simpleDecrypter = new SimpleDecrypter();
        thiefDecrypter = new SimpleDecrypter();
    }

    function test_mock_InEuintXX() public {
        address bob = makeAddr("bob");
        {
            bool boolValue = true;
            Ebool memory EboolValue = FHT.createEbool(boolValue, bob);
            FHT.assertHashValue(EboolValue.ctHash, 1);
        }

        {
            uint8 uint8Value = 10;
            Euint8 memory Euint8Value = FHT.createEuint8(uint8Value, bob);
            FHT.assertHashValue(Euint8Value.ctHash, uint8Value);
        }

        {
            uint16 uint16Value = 1000;
            Euint16 memory Euint16Value = FHT.createEuint16(
                uint16Value,
                bob
            );
            FHT.assertHashValue(Euint16Value.ctHash, uint16Value);
        }

        {
            uint32 uint32Value = 1000000;
            Euint32 memory Euint32Value = FHT.createEuint32(
                uint32Value,
                bob
            );
            FHT.assertHashValue(Euint32Value.ctHash, uint32Value);
        }

        {
            uint64 uint64Value = 1000000000;
            Euint64 memory Euint64Value = FHT.createEuint64(
                uint64Value,
                bob
            );
            FHT.assertHashValue(Euint64Value.ctHash, uint64Value);
        }

        {
            uint128 uint128Value = 1000000000000;
            Euint128 memory Euint128Value = FHT.createEuint128(
                uint128Value,
                bob
            );
            FHT.assertHashValue(Euint128Value.ctHash, uint128Value);
        }

        {
            uint256 uint256Value = 1000000000000000;
            Euint256 memory Euint256Value = FHT.createEuint256(
                uint256Value,
                bob
            );
            FHT.assertHashValue(Euint256Value.ctHash, uint256Value);
        }

        {
            address addressValue = 0x888888CfAebbEd5554c3F36BfBD233f822e9455f;
            Eaddress memory EaddressValue = FHT.createEaddress(
                addressValue,
                bob
            );
            FHT.assertHashValue(
                EaddressValue.ctHash,
                uint256(uint160(addressValue))
            );
        }
    }

    function test_mock_select() public {
        bool boolValue = true;
        ebool eboolValue = FHE.asEbool(boolValue);

        uint32 uint32A = 10;
        uint32 uint32B = 20;

        euint32 euintA = FHE.asEuint32(uint32A);
        euint32 euintB = FHE.asEuint32(uint32B);

        euint32 euintC = FHE.select(eboolValue, euintA, euintB);

        FHT.assertHashValue(euint32.unwrap(euintC), uint32A);

        boolValue = false;
        eboolValue = FHE.asEbool(boolValue);

        euintC = FHE.select(eboolValue, euintA, euintB);

        FHT.assertHashValue(euint32.unwrap(euintC), uint32B);
    }

    function test_mock_euint32_operations() public {
        uint32 a = 100;
        uint32 b = 50;

        // Convert to encrypted values
        euint32 ea = FHE.asEuint32(a);
        euint32 eb = FHE.asEuint32(b);

        // Test unary operations
        {
            // Test not (only works on ebool)
            ebool eboolVal = FHE.asEbool(true);
            ebool notResult = FHE.not(eboolVal);
            FHT.assertHashValue(notResult, false);
        }
        {
            // Test square
            euint32 squared = FHE.square(ea);
            FHT.assertHashValue(squared, a * a);
        }

        // Test two-input operations
        {
            // Arithmetic operations
            euint32 sum = FHE.add(ea, eb);
            FHT.assertHashValue(sum, a + b);
        }
        {
            // Test subtraction
            euint32 diff = FHE.sub(ea, eb);
            FHT.assertHashValue(diff, a - b);
        }
        {
            // Test multiplication
            euint32 prod = FHE.mul(ea, eb);
            FHT.assertHashValue(prod, a * b);
        }
        {
            // Test division
            euint32 div = FHE.div(ea, eb);
            FHT.assertHashValue(div, a / b);
        }
        {
            // Test remainder
            euint32 rem = FHE.rem(ea, eb);
            FHT.assertHashValue(rem, a % b);
        }

        // Bitwise operations
        {
            // Test bitwise AND
            euint32 andResult = FHE.and(ea, eb);
            FHT.assertHashValue(andResult, a & b);
        }
        {
            // Test bitwise OR
            euint32 orResult = FHE.or(ea, eb);
            FHT.assertHashValue(orResult, a | b);
        }
        {
            // Test bitwise XOR
            euint32 xorResult = FHE.xor(ea, eb);
            FHT.assertHashValue(xorResult, a ^ b);
        }

        // Shift operations
        uint32 shift = 2;
        {
            // Test shift left
            euint32 es = FHE.asEuint32(shift);

            euint32 shl = FHE.shl(ea, es);
            FHT.assertHashValue(shl, a << shift);
        }
        {
            // Test shift right
            euint32 es = FHE.asEuint32(shift);

            euint32 shr = FHE.shr(ea, es);
            FHT.assertHashValue(shr, a >> shift);
        }
        {
            // Test rol
            euint32 es = FHE.asEuint32(shift);

            euint32 rol = FHE.rol(ea, es);
            FHT.assertHashValue(rol, a << shift); // Note: rol is implemented as shl in the mock
        }
        {
            // Test ror
            euint32 es = FHE.asEuint32(shift);

            euint32 ror = FHE.ror(ea, es);
            FHT.assertHashValue(ror, a >> shift); // Note: ror is implemented as shr in the mock
        }

        // Comparison operations
        {
            // Test greater than
            ebool gt = FHE.gt(ea, eb);
            FHT.assertHashValue(gt, a > b);
        }
        {
            // Test less than
            ebool lt = FHE.lt(ea, eb);
            FHT.assertHashValue(lt, a < b);
        }
        {
            // Test greater than or equal to
            ebool gte = FHE.gte(ea, eb);
            FHT.assertHashValue(gte, a >= b);
        }
        {
            // Test less than or equal to
            ebool lte = FHE.lte(ea, eb);
            FHT.assertHashValue(lte, a <= b);
        }
        {
            // Test equal to
            ebool eq = FHE.eq(ea, eb);
            FHT.assertHashValue(eq, a == b);
        }
        {
            // Test not equal to
            ebool ne = FHE.ne(ea, eb);
            FHT.assertHashValue(ne, a != b);
        }

        // Min/Max operations
        {
            // Test min
            euint32 min = FHE.min(ea, eb);
            FHT.assertHashValue(min, a < b ? a : b);
        }
        {
            // Test max
            euint32 max = FHE.max(ea, eb);
            FHT.assertHashValue(max, a > b ? a : b);
        }
    }

    function test_mock_decrypt() public {
        uint160 userAddress = 512;

        uint8 uint8Value = 10;
        Euint8 memory Euint8Value = FHT.createEuint8(
            uint8Value,
            address(userAddress)
        );

        vm.prank(address(userAddress));
        simpleDecrypter.decrypt(Euint8Value);

        // In mocks, this happens synchronously
        vm.warp(block.timestamp + 11);
        uint256 result = simpleDecrypter.getDecryptResult(Euint8Value.ctHash);

        assertEq(result, uint8Value);
    }

    error ACLNotAllowed(uint256 handle, address account);

    function test_ACL_not_allowed() public {
        uint8 uint8Value = 10;
        Euint8 memory Euint8Value = FHT.createEuint8(
            uint8Value,
            msg.sender
        );

        euint8 euint8Value = FHE.asEuint8(Euint8Value);

        // Decrypt reverts (not allowed yet)

        vm.expectRevert(
            abi.encodeWithSelector(
                ACLNotAllowed.selector,
                Euint8Value.ctHash,
                address(thiefDecrypter)
            )
        );

        thiefDecrypter.decrypt(euint8Value);

        // Allow decrypt

        FHE.allow(euint8Value, address(thiefDecrypter));

        // Decrypt succeeds

        thiefDecrypter.decrypt(euint8Value);

        vm.warp(block.timestamp + 11);
        assertEq(
            thiefDecrypter.getDecryptResult(Euint8Value.ctHash),
            uint8Value
        );
    }
}
