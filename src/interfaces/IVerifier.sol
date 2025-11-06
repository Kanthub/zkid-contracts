// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVerifier {
    function verifyProof(bytes calldata proof, uint256[] calldata pubInputs) external view returns (bool);
}
