// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";

import "../interfaces/IBLSApkRegistry.sol";
import "../interfaces/IOracleKYCPod.sol";
import "./PodManager.sol";

/**
 * @title OracleKYCManager
 * @notice 由 Oracle 方部署，用于验证聚合签名并在 Oracle Pod 合约中登记结果。
 * @dev 注意：不再使用 did 作为索引，而是用 user 地址登记。
 */
contract OracleKYCManager is Initializable, OwnableUpgradeable, PodManager {
    event KYCVerified(
        address indexed user,
        uint256 commitment,
        bytes32 signPodHash,
        uint256 totalStake
    );

    function initialize(
        address _initialOwner,
        address _blsApkRegistry,
        address _aggregatorManager
    ) external initializer {
        __Ownable_init(_initialOwner);
        __PodManager_init(_blsApkRegistry, _aggregatorManager);
    }

    /**
     * @notice Oracle节点提交KYC验证结果并登记承诺
     * @param oraclePod Oracle KYC Pod合约地址
     * @param user 用户钱包地址
     * @param commitment C = Poseidon(m, did, policy_id, version)
     * @param msgHash Oracle签名消息哈希
     * @param refBlock 验签基于的区块号
     * @param oracleSig 聚合签名结构体
     */
    function verifyAndPodKYC(
        IOracleKYCPod oraclePod,
        address user,
        uint256 commitment,
        bytes32 msgHash,
        uint32 refBlock,
        IBLSApkRegistry.NonSignerAndSignature memory oracleSig
    ) external onlyAggregatorManager {
        // 验证 Oracle 聚合签名
        (uint256 totalStake, bytes32 signPodHash) = blsApkRegistry
            .checkSignatures(msgHash, refBlock, oracleSig);

        // 状态登记
        oraclePod.recordVerification(user, commitment);

        emit KYCVerified(user, commitment, signPodHash, totalStake);
    }

    uint256[50] private __gap;
}
