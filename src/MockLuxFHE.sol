// SPDX-License-Identifier: BSD-3-Clause-Clear
// Backwards compatibility - re-exports from MockFHE
pragma solidity >=0.8.25 <0.9.0;

// Re-export constants from MockFHE
import {SIGNER_ADDRESS, SIGNER_PRIVATE_KEY, MockFHE as MockLuxFHE} from "./MockFHE.sol";

// Re-export EncryptedInput from FHE contracts
import {EncryptedInput} from "@luxfi/contracts/fhe/IFHE.sol";
