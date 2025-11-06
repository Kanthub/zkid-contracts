// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";

import "../interfaces/IOracleKYCPod.sol";

/**
 * @title OracleKYCPod
 * @notice 存储每个用户的KYC验证结果与承诺值C。
 * @dev 以用户地址为键；did不暴露在链上。
 */
contract OracleKYCPod is Initializable, OwnableUpgradeable, IOracleKYCPod {
    mapping(address => Record) public kycRecords; // user => Record

    event KYCRecorded(address indexed user, bytes32 commitment, bytes32 signRecordHash, uint32 refBlock);

    function initialize(address _initialOwner) external initializer {
        __Ownable_init(_initialOwner);
    }

    /**
     * @notice 记录用户的KYC验证结果
     * @dev 仅OracleKYCManager(Owner)可调用
     *
     * Commitment = Poseidon(m, r, did, policy_id, version)
     *   m：用户私有的 KYC 明文（如 age、nationality）
     *         r：随机盐（或 derived from did）
     *         did：隐私身份标识
     *         policy_id / version：策略上下文
     */
    function recordVerification(
        address user,
        bytes32 commitment,
        bytes32 msgHash,
        bytes32 signRecordHash,
        uint32 refBlock
    ) external onlyOwner {
        Record storage rec = kycRecords[user];
        rec.commitment = commitment;
        rec.msgHash = msgHash;
        rec.signRecordHash = signRecordHash;
        rec.refBlock = refBlock;
        rec.verified = true;

        emit KYCRecorded(user, commitment, signRecordHash, refBlock);
    }

    function isVerified(address user) external view returns (bool) {
        return kycRecords[user].verified;
    }

    function getRecord(address user) external view returns (Record memory) {
        return kycRecords[user];
    }

    function getCommitment(address user) external view returns (bytes32) {
        return kycRecords[user].commitment;
    }

    uint256[50] private __gap;
}
