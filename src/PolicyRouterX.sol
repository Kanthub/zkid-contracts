// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./libraries/OracleSigVerifier.sol";
import "./interfaces/IBLSApkRegistryX.sol";
import "./interfaces/IVerifier.sol";

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "./libraries/BN254.sol";

/// @title PolicyRouter
/// @notice 上层设计, Layer 3: zkID Policy Verifier & Oracle Router
///         - 根据不同的 policyId 路由到相应的 Oracle Registry
///         - 调用 OracleSigVerifier.verify() 验签 BLS 签名
///         - （预留）调用 zk proof verifier 验证零知识证明
contract PolicyRouterX is Initializable, OwnableUpgradeable {
    using OracleSigVerifier for *;

    // ============================ Events ===============================
    event Verified(
        uint256 policyId,
        uint256 version,
        string zkVerifierDescription,
        address indexed zkVerifier,
        address indexed verifierCaller
    );

    // ============================ Storage ================================

    /// @dev policyId => BLS Registry 地址
    mapping(uint256 => IBLSApkRegistryX) public policyToRegistry;
    /// @dev policyId => 最新版本号
    mapping(uint256 => uint256) public latestPolicyVersion;
    /// @dev zk proof verifier 地址（可选，后续接入）
    mapping(string => IVerifier) public zkVerifiers;

    // ============================ Functions ==============================

    /// @notice 初始化合约
    function initialize(address _initialOwner) public initializer {
        __Ownable_init(_initialOwner);
    }

    /// @dev 设置 zkVerifier，选择是判断年龄、国籍等不同策略时使用不同的 verifier
    /// @dev 也可设置为 address(0) 以跳过 zk proof 验证
    /// @param description 验证器描述，如 "age_over_18"
    /// @param _verifier   验证器合约地址
    function setZkVerifier(string memory description, address _verifier) external onlyOwner {
        zkVerifiers[description] = IVerifier(_verifier);
    }

    /// @dev 为某个 policy 绑定对应 Oracle Registry
    /// @dev 也起到注册Oracle Registry的作用
    /// @param policyId 业务策略 ID
    /// @param registry Oracle Registry 合约地址
    function setPolicyRegistry(uint256 policyId, address registry) external onlyOwner {
        policyToRegistry[policyId] = IBLSApkRegistryX(registry);
    }

    /// @dev 更新某个 policy 的最新版本号
    /// @param policyId 业务策略 ID
    /// @param version  最新版本号
    function setLatestPolicyVersion(uint256 policyId, uint256 version) external onlyOwner {
        latestPolicyVersion[policyId] = version;
    }

    // =============== 验证逻辑 1 ===============

    /// @notice BLS + ZK 验证总流程
    /// @param policyId    业务策略 ID
    /// @param version     策略版本号
    /// @param refBlock    Oracle 签名绑定的参考区块
    /// @param apkHash     当时聚合 G1 公钥快照哈希
    /// @param sigma       聚合签名 (G1)
    /// @param P           消息点 (G1)
    /// @param apkG2       聚合公钥 (G2)
    /// @param proof       zk proof（占位）
    /// @param pubInputs   zk proof 公开输入（占位）
    function verifyAll(
        uint256 policyId,
        uint256 version,
        uint32 refBlock,
        bytes24 apkHash,
        BN254.G1Point calldata sigma,
        BN254.G1Point calldata P,
        BN254.G2Point calldata apkG2,
        bytes calldata proof,
        uint256[] calldata pubInputs,
        string memory zkVerifierDescription
    ) external returns (bool) {
        // 1. 根据 policy_id 找到对应的 Oracle Registry
        require(version == latestPolicyVersion[policyId], "PolicyRouter: policy version mismatch"); // 要求匹配Oracle最新版本
        IBLSApkRegistryX registry = policyToRegistry[policyId];
        require(address(registry) != address(0), "PolicyRouter: registry not set");

        // 2. 先做 Oracle 验签
        bool ok = OracleSigVerifier.verify(registry, refBlock, apkHash, sigma, P, apkG2);
        require(ok, "PolicyRouter: oracle sig invalid");

        // 3.（预留）验证 zk proof（此处先返回 true 或空逻辑）
        IVerifier zkVerifier = zkVerifiers[zkVerifierDescription];
        require(address(zkVerifier) != address(0), "PolicyRouter: zk verifier not set");
        require(zkVerifier.verifyProof(proof, pubInputs), "PolicyRouter: zk proof invalid");

        emit Verified(policyId, version, zkVerifierDescription, address(zkVerifier), msg.sender);
        return true;
    }

    // =============== 验证逻辑 2 ===============

    /// @notice 预留第二套逻辑方案：即Oracle每一次更新version，都会重新部署一个新的registry合约
    /// @notice 因此registry地址由policyId和version共同决定

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
    //     // 1. 根据 policy_id 和 version 找到对应的 Oracle Registry
    //     IBLSApkRegistryX registry = policyToRegistry[policyId][version];
    //     require(
    //         address(registry) != address(0),
    //         "PolicyRouter: registry not set"
    //     );

    //     // 2. 先做 Oracle 验签
    //     bool ok = OracleSigVerifier.verify(
    //         registry,
    //         refBlock,
    //         apkHash,
    //         sigma,
    //         P,
    //         apkG2
    //     );
    //     require(ok, "PolicyRouter: oracle sig invalid");

    //    // 3.（预留）验证 zk proof（此处先返回 true 或空逻辑）
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
