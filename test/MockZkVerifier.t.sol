// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {FHETest} from "../src/FHETest.sol";
import {EncryptedInput} from "../src/MockLuxFHE.sol";
import "@luxfi/contracts/fhe/FHE.sol";

contract MockZkVerifierTests is Test {
    FHETest FHT;

    function setUp() public {
        FHT = new FHETest(false);
    }

    function test_zkVerify() public {
        address sender = address(128);

        EncryptedInput memory input = FHT.zkVerifier().zkVerify(
            5,
            Utils.EUINT8_TFHE,
            sender,
            0,
            block.chainid
        );

        input = FHT.zkVerifierSigner().zkVerifySign(input, sender);

        // Hash should be in storage
        FHT.assertHashValue(input.ctHash, 5);

        // Signature should be valid
        FHT.fheNetwork().verifyInput(input, sender);
    }

    function test_zkVerifyPacked() public {
        uint8[] memory utypes = new uint8[](2);
        utypes[0] = Utils.EUINT8_TFHE;
        utypes[1] = Utils.EUINT8_TFHE;

        uint256[] memory values = new uint256[](2);
        values[0] = 5;
        values[1] = 6;

        address sender = address(128);

        EncryptedInput[] memory inputs = FHT.zkVerifier().zkVerifyPacked(
            values,
            utypes,
            sender,
            0,
            block.chainid
        );

        inputs = FHT.zkVerifierSigner().zkVerifySignPacked(inputs, sender);

        // Hash should be in storage
        FHT.assertHashValue(inputs[0].ctHash, 5);
        FHT.assertHashValue(inputs[1].ctHash, 6);

        FHT.fheNetwork().verifyInput(inputs[0], sender);
        FHT.fheNetwork().verifyInput(inputs[1], sender);
    }

    function test_zkVerifier_as_mock() public {
        address sender = address(128);

        uint8[] memory utypes = new uint8[](2);
        utypes[0] = Utils.EUINT8_TFHE;
        utypes[1] = Utils.EUINT8_TFHE;

        uint256[] memory values = new uint256[](2);
        values[0] = 5;
        values[1] = 6;

        uint256[] memory ctHashes = FHT.zkVerifier().zkVerifyCalcCtHashesPacked(
            values,
            utypes,
            sender,
            0,
            block.chainid
        );

        FHT.zkVerifier().insertPackedCtHashes(ctHashes, values);

        // Hash should be in storage
        FHT.assertHashValue(ctHashes[0], 5);
        FHT.assertHashValue(ctHashes[1], 6);
    }
}
