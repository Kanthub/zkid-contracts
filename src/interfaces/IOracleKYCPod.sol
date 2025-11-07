// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracleKYCPod {
    struct Record {
        uint256 commitment; // Poseidon(m, did, policy_id, version)
        bool verified; // 是否已验证成功
    }

    /// @notice 记录KYC验证结果（仅管理合约可调用）
    function recordVerification(address user, uint256 commitment) external;

    /// @notice 查询某个DID是否已验证
    function isVerified(address user) external view returns (bool);

    /// @notice 查询完整记录
    function getRecord(address user) external view returns (Record memory);

    function getCommitment(address user) external view returns (uint256);
}
