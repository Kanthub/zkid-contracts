// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./libraries/OracleSigVerifier.sol";
import "./interfaces/IBLSApkRegistryX.sol";
import "./interfaces/IVerifier.sol";

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "./libraries/BN254.sol";

/// @title PolicyRouter
/// @notice Top-level design, Layer 3: zkID Policy Verifier & Oracle Router
///         - Route to the corresponding Oracle Registry based on policyId
///         - Call OracleSigVerifier.verify() to verify the BLS signature
///         - (Reserved) Call a zk proof verifier to verify a zero-knowledge proof
contract PolicyRouterX is Initializable, OwnableUpgradeable {
    using OracleSigVerifier for *;

    // ============================ Events ===============================
    event Verified(uint256 policyId, uint256 version, string zkVerifierDescription, address indexed zkVerifier, address indexed verifierCaller);

    // ============================ Storage ================================

    /// @dev policyId => BLS Registry address
    mapping(uint256 => IBLSApkRegistryX) public policyToRegistry;
    /// @dev policyId => latest version
    mapping(uint256 => uint256) public latestPolicyVersion;
    /// @dev zk proof verifier address (optional, to be integrated later)
    mapping(string => IVerifier) public zkVerifiers;

    // ============================ Functions ==============================

    /// @notice Initialize the contract
    function initialize(address _initialOwner) public initializer {
        __Ownable_init(_initialOwner);
    }

    /// @dev Set a zkVerifier; use different verifiers for different policies such as age, nationality, etc.
    /// @dev Can also be set to address(0) to skip zk proof verification
    /// @param description Verifier description, e.g. "age_over_18"
    /// @param _verifier   Verifier contract address
    function setZkVerifier(string memory description, address _verifier) external onlyOwner {
        zkVerifiers[description] = IVerifier(_verifier);
    }

    /// @dev Bind an Oracle Registry for a given policy
    /// @dev Also serves as registering the Oracle Registry
    /// @param policyId Business policy ID
    /// @param registry Oracle Registry contract address
    function setPolicyRegistry(uint256 policyId, address registry) external onlyOwner {
        policyToRegistry[policyId] = IBLSApkRegistryX(registry);
    }

    /// @dev Update the latest version for a given policy
    /// @param policyId Business policy ID
    /// @param version  Latest version
    function setLatestPolicyVersion(uint256 policyId, uint256 version) external onlyOwner {
        latestPolicyVersion[policyId] = version;
    }

    // =============== Verification Logic 1 ===============

    /// @notice End-to-end BLS + ZK verification flow
    /// @param policyId    Business policy ID
    /// @param version     Policy version
    /// @param refBlock    Reference block bound to the Oracle signature
    /// @param apkHash     Snapshot hash of the aggregated G1 public key at that time
    /// @param sigma       Aggregated signature (G1)
    /// @param P           Message point (G1)
    /// @param apkG2       Aggregated public key (G2)
    /// @param proof       zk proof (placeholder)
    /// @param pubInputs   Public inputs for the zk proof (placeholder)
    function verifyAll(uint256 policyId, uint256 version, uint32 refBlock, bytes24 apkHash, BN254.G1Point calldata sigma, BN254.G1Point calldata P, BN254.G2Point calldata apkG2, bytes calldata proof, uint256[] calldata pubInputs, string memory zkVerifierDescription) external returns (bool) {
        // 1. Find the corresponding Oracle Registry by policyId
        require(version == latestPolicyVersion[policyId], "PolicyRouter: policy version mismatch"); // Must match the latest Oracle version
        IBLSApkRegistryX registry = policyToRegistry[policyId];
        require(address(registry) != address(0), "PolicyRouter: registry not set");

        // 2. Verify the Oracle signature first
        bool ok = OracleSigVerifier.verify(registry, refBlock, apkHash, sigma, P, apkG2);
        require(ok, "PolicyRouter: oracle sig invalid");

        // 3. (Reserved) Verify the zk proof (currently required and executed)
        IVerifier zkVerifier = zkVerifiers[zkVerifierDescription];
        require(address(zkVerifier) != address(0), "PolicyRouter: zk verifier not set");
        require(zkVerifier.verifyProof(proof, pubInputs), "PolicyRouter: zk proof invalid");

        emit Verified(policyId, version, zkVerifierDescription, address(zkVerifier), msg.sender);
        return true;
    }

    // =============== Verification Logic 2 ===============

    /// @notice Reserved alternative logic: each time Oracle updates the version, it deploys a new registry contract
    /// @notice Therefore, the registry address is determined by policyId and version together

    // function verifyAllPlus(
    //     uint256 policyId,
    //     uint256 version,
    //     uint32 refBlock,
    //     bytes24 apkHash,
    //     BN254.G1Point calldata sigma,
    //     BN254.G1Point calldata P,
    //     BN254.G2Point calldata apkG2,
    //     bytes calldata proof,
    //     uint256[] calldata pubInputs
    // ) external view returns (bool) {
    //     // 1. Find the corresponding Oracle Registry by policyId and version
    //     IBLSApkRegistryX registry = policyToRegistry[policyId][version];
    //     require(
    //         address(registry) != address(0),
    //         "PolicyRouter: registry not set"
    //     );

    //     // 2. Verify the Oracle signature first
    //     bool ok = OracleSigVerifier.verify(
    //         registry,
    //         refBlock,
    //         apkHash,
    //         sigma,
    //         P,
    //         apkG2
    //     );
    //     require(ok, "PolicyRouter: oracle sig invalid");

    //    // 3. (Reserved) Verify the zk proof (currently returns true / empty logic)
    //         IVerifier zkVerifier = zkVerifiers[zkVerifierDescription];
    //         require(
    //             address(zkVerifier) != address(0),
    //             "PolicyRouter: zk verifier not set"
    //         );
    //         require(
    //             zkVerifier.verifyProof(proof, pubInputs),
    //             "PolicyRouter: zk proof invalid"
    //         );

    // emit Verified(
    //         policyId,
    //         version,
    //         zkVerifierDescription,
    //         address(zkVerifier),
    //         msg.sender
    //     );
    //         return true;
    // }

    uint256[50] private __gap;
}
