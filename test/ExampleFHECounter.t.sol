// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ExampleFHECounter} from "./ExampleFHECounter.sol";
import {FHETest} from "../src/FHETest.sol";
import "@luxfi/contracts/fhe/FHE.sol";

contract ExampleFHECounterTest is Test {
    FHETest FHT;
    address bob = makeAddr("bob");

    ExampleFHECounter public counter;

    function setUp() public {
        FHT = new FHETest(false);

        counter = new ExampleFHECounter();

        // Set number to 5
        Euint32 memory inNumber = FHT.createEuint32(5, bob);
        vm.prank(bob);
        counter.setNumber(inNumber);
    }

    function test_setNumber() public {
        Euint32 memory inNumber = FHT.createEuint32(10, bob);
        vm.prank(bob);
        counter.setNumber(inNumber);
        FHT.assertHashValue(counter.eNumber(), 10);
    }

    function test_increment() public {
        counter.increment();
        FHT.assertHashValue(counter.eNumber(), 6);
    }

    function test_add() public {
        Euint32 memory inNumber = FHT.createEuint32(2, bob);
        vm.prank(bob);
        counter.add(inNumber);
        FHT.assertHashValue(counter.eNumber(), 7);
    }

    function test_sub() public {
        Euint32 memory inNumber = FHT.createEuint32(3, bob);
        vm.prank(bob);
        counter.sub(inNumber);
        FHT.assertHashValue(counter.eNumber(), 2);
    }

    function test_mul() public {
        Euint32 memory inNumber = FHT.createEuint32(2, bob);
        vm.prank(bob);
        counter.mul(inNumber);
        FHT.assertHashValue(counter.eNumber(), 10);
    }

    function test_decrypt() public {
        FHT.assertHashValue(counter.eNumber(), 5);
        counter.decrypt();

        uint8 count = 0;
        bool success = false;
        while (!success && count < 100) {
            try counter.getDecryptResult(counter.eNumber()) returns (uint32) {
                success = true;
            } catch {
                vm.warp(block.timestamp + 1);
                count += 1;
            }
        }
    }

    function test_decryptSafe() public {
        FHT.assertHashValue(counter.eNumber(), 5);
        counter.decrypt();

        uint8 count = 0;
        bool success = false;
        while (!success && count < 100) {
            (uint256 result, bool decrypted) = counter.getDecryptResultSafe(
                counter.eNumber()
            );
            if (decrypted) {
                assertEq(result, 5);
                success = true;
            } else {
                vm.warp(block.timestamp + 1);
                count += 1;
            }
        }
    }
}
