// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IBLSApkRegistryX.sol";
import "../libraries/BN254.sol";

/// @title OracleSigVerifier
/// @notice Layer2 中间层：
///         DApp 可选择不同的 BLS Registry 合约进行验证，
///         只验证签名合法性，不接触用户明文或 KYC 数据。
library OracleSigVerifier {
    using BN254 for *;

    /// @notice 按快照 + pairing 的隐私安全验签逻辑
    /// @param registry   Oracle Registry 地址（维护聚合公钥快照）
    /// @param refBlock   签名时绑定的参考区块高度
    /// @param apkHash    当时的聚合 G1 公钥哈希（Registry 快照）
    /// @param sigma      聚合签名（G1）
    /// @param P          由 Oracle 链下计算的消息点（G1），即 hashToG1(msgHash)
    /// @param apkG2      聚合公钥（G2），由 Oracle 链下签发时一并返回
    function verify(
        IBLSApkRegistryX registry,
        uint32 refBlock,
        bytes24 apkHash,
        BN254.G1Point memory sigma,
        BN254.G1Point memory P,
        BN254.G2Point memory apkG2
    ) internal view returns (bool ok) {
        // 1. 确认聚合公钥快照一致性，防止用户伪造 apkG2 配合旧签名
        require(registry.isApkHashValidAt(apkHash, refBlock), "OracleSigVerifier: apk snapshot mismatch");
        // 取历史快照的 G1 公钥
        BN254.G1Point memory apkG1 = registry.apkHashAt(refBlock);

        // 校验 apkG1 与 apkG2 的一致性
        // e(apkG1, g2) == e(g1, apkG2)
        bool keyMatch = BN254.pairing(apkG1, BN254.generatorG2(), BN254.generatorG1(), apkG2);
        require(keyMatch, "OracleSigVerifier: apkG1/apkG2 mismatch");

        // 2.  pairing 验签： e(σ, g2) == e(P, apkG2)
        //    - σ: 聚合签名 (G1)
        //    - g2: 固定曲线生成元 (G2)
        //    - P: Oracle 链下 hashToG1(msgHash)
        //    - apkG2: 当时聚合公钥 (G2)
        bool pairingOk = BN254.pairing(sigma, BN254.generatorG2(), P, apkG2); // 不在registry合约验证，因为registry的聚合公钥在实时更新，无法保证一致性
        require(pairingOk, "OracleSigVerifier: pairing failed");

        // 3. 验证通过
        ok = true;
    }
}
