// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * Secret Resume Filter (Zama FHEVM)
 *
 * Project language: English (code & comments)
 * Chat language: Russian
 *
 * Overview
 * - Employers create positions with encrypted criteria.
 * - Candidates submit encrypted attributes; contract computes an encrypted verdict (ebool).
 * - Only the employer for that position can decrypt the verdict (userDecrypt path).
 *
 * Encrypted candidate fields:
 *   - yearsExp:   euint8   (>= minExp)
 *   - eduLevel:   euint8   (>= minEdu)          // 0=None,1=HS,2=Bachelor,3=Master,4=PhD
 *   - skillsMask: euint16  (must contain all requiredSkills bits)
 *   - expSalary:  euint32  (<= maxSalary)
 *
 * Notes:
 * - Uses only official Zama FHE library & SepoliaConfig.
 * - Avoid FHE operations in view/pure (we only expose handles via FHE.toBytes32 in view).
 * - euint256/eaddress arithmetic not used.
 */

import {
    FHE,
    ebool,
    euint8,
    euint16,
    euint32,
    externalEuint8,
    externalEuint16,
    externalEuint32
} from "@fhevm/solidity/lib/FHE.sol";

import { SepoliaConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract SecretResumeFilter is SepoliaConfig {
    /* ─────────────────────── Admin / Ownership ─────────────────────── */

    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }

    constructor() { owner = msg.sender; }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero owner");
        owner = newOwner;
    }

    /* ─────────────────────── Data Structures ─────────────────────── */

    struct Criteria {
        // Encrypted criteria
        euint8   minExp;         // candidate.yearsExp >= minExp
        euint8   minEdu;         // candidate.eduLevel >= minEdu
        euint16  requiredSkills; // (candidate.skillsMask & requiredSkills) == requiredSkills
        euint32  maxSalary;      // candidate.expSalary <= maxSalary

        // Meta
        address  employer;       // who gets decrypt rights for verdicts
        bool     exists;
    }

    // positionId => Criteria
    mapping(uint256 => Criteria) private _criteria;

    /* ─────────────────────────── Events ─────────────────────────── */

    event PositionCreated(uint256 indexed positionId, address indexed employer);

    event CriteriaUpdated(
        uint256 indexed positionId,
        bytes32 minExpH,
        bytes32 minEduH,
        bytes32 requiredSkillsH,
        bytes32 maxSalaryH
    );

    /// @dev Emitted on each application; verdictHandle is an ebool.
    event ApplicationEvaluated(
        uint256 indexed positionId,
        address indexed candidate,   // msg.sender
        address indexed employer,    // criteria.employer
        bytes32 verdictHandle
    );

    /* ────────────────────────── Modifiers ────────────────────────── */

    modifier onlyEmployer(uint256 positionId) {
        Criteria storage c = _criteria[positionId];
        require(c.exists, "Position not found");
        require(c.employer == msg.sender, "Not employer");
        _;
    }

    /* ─────────────────────── Position Management ─────────────────────── */

    /**
     * @notice Create a position entry with employer address.
     *         Criteria must be set separately (encrypted or plain dev setter).
     */
    function createPosition(uint256 positionId, address employer) external onlyOwner {
        require(positionId != 0, "Bad positionId");
        require(employer != address(0), "Zero employer");
        require(!_criteria[positionId].exists, "Position exists");

        _criteria[positionId].employer = employer;
        _criteria[positionId].exists = true;

        emit PositionCreated(positionId, employer);
    }

    /**
     * @notice Change employer for a position (e.g., handover).
     */
    function setEmployer(uint256 positionId, address newEmployer) external onlyEmployer(positionId) {
        require(newEmployer != address(0), "Zero employer");
        _criteria[positionId].employer = newEmployer;
    }

    /**
     * @notice Remove a position (marks absent; encrypted values remain unused).
     *         Do not try to delete euint values — just mark as non-existing.
     */
    function removePosition(uint256 positionId) external onlyEmployer(positionId) {
        _criteria[positionId].exists = false;
        _criteria[positionId].employer = address(0);
    }

    /* ─────────────────────── Criteria Management ─────────────────────── */

    /**
     * @notice Set encrypted criteria for a position (official Relayer SDK proof).
     */
    function setCriteriaEncrypted(
        uint256 positionId,
        externalEuint8  minExpExt,
        externalEuint8  minEduExt,
        externalEuint16 reqSkillsExt,
        externalEuint32 maxSalaryExt,
        bytes calldata  proof
    ) external onlyEmployer(positionId) {
        // Deserialize with proof attestation
        euint8  minExpCt    = FHE.fromExternal(minExpExt,    proof);
        euint8  minEduCt    = FHE.fromExternal(minEduExt,    proof);
        euint16 reqSkillsCt = FHE.fromExternal(reqSkillsExt, proof);
        euint32 maxSalaryCt = FHE.fromExternal(maxSalaryExt, proof);

        // Store
        Criteria storage c = _criteria[positionId];
        c.minExp         = minExpCt;
        c.minEdu         = minEduCt;
        c.requiredSkills = reqSkillsCt;
        c.maxSalary      = maxSalaryCt;

        // Allow contract to reuse these ciphertexts across txs
        FHE.allowThis(c.minExp);
        FHE.allowThis(c.minEdu);
        FHE.allowThis(c.requiredSkills);
        FHE.allowThis(c.maxSalary);

        emit CriteriaUpdated(
            positionId,
            FHE.toBytes32(c.minExp),
            FHE.toBytes32(c.minEdu),
            FHE.toBytes32(c.requiredSkills),
            FHE.toBytes32(c.maxSalary)
        );
    }

    /**
     * @notice DEV ONLY: set plain criteria (converts to encrypted on-chain).
     */
    function setCriteriaPlain(
        uint256 positionId,
        uint8  minExp,
        uint8  minEdu,
        uint16 requiredSkills,
        uint32 maxSalary
    ) external onlyEmployer(positionId) {
        Criteria storage c = _criteria[positionId];

        c.minExp         = FHE.asEuint8(minExp);
        c.minEdu         = FHE.asEuint8(minEdu);
        c.requiredSkills = FHE.asEuint16(requiredSkills);
        c.maxSalary      = FHE.asEuint32(maxSalary);

        FHE.allowThis(c.minExp);
        FHE.allowThis(c.minEdu);
        FHE.allowThis(c.requiredSkills);
        FHE.allowThis(c.maxSalary);

        emit CriteriaUpdated(
            positionId,
            FHE.toBytes32(c.minExp),
            FHE.toBytes32(c.minEdu),
            FHE.toBytes32(c.requiredSkills),
            FHE.toBytes32(c.maxSalary)
        );
    }

    /**
     * @notice Optional: expose handles for audits (decryptability depends on ACL/public flags).
     */
    function getCriteriaHandles(uint256 positionId)
        external
        view
        returns (bytes32 minExpH, bytes32 minEduH, bytes32 reqSkillsH, bytes32 maxSalaryH, address employer)
    {
        require(_criteria[positionId].exists, "Position not found");
        Criteria storage c = _criteria[positionId];
        return (
            FHE.toBytes32(c.minExp),
            FHE.toBytes32(c.minEdu),
            FHE.toBytes32(c.requiredSkills),
            FHE.toBytes32(c.maxSalary),
            c.employer
        );
    }

    /**
     * @notice Optional demo: mark stored criteria publicly decryptable.
     *         NOT recommended for production.
     */
    function makeCriteriaPublic(uint256 positionId) external onlyEmployer(positionId) {
        Criteria storage c = _criteria[positionId];
        FHE.makePubliclyDecryptable(c.minExp);
        FHE.makePubliclyDecryptable(c.minEdu);
        FHE.makePubliclyDecryptable(c.requiredSkills);
        FHE.makePubliclyDecryptable(c.maxSalary);
    }

    /* ─────────────────────── Resume Evaluation ─────────────────────── */

    /**
     * @notice Candidate submits encrypted attributes; contract returns encrypted verdict.
     *         Verdict semantics: 1 = FIT, 0 = NO_FIT.
     *
     * Access control:
     *  - Decryption right is granted ONLY to the employer of the position.
     *  - We also allowThis(verdict) so the contract can reuse during the tx if needed.
     *
     * @param positionId    target position
     * @param yearsExpExt   externalEuint8
     * @param eduLevelExt   externalEuint8
     * @param skillsMaskExt externalEuint16 (bitmask)
     * @param expSalaryExt  externalEuint32 (expected salary)
     * @param proof         attestation from Relayer SDK (batch)
     *
     * @return verdictCt    ebool (1=fit / 0=no fit)
     */
    function evaluateApplication(
        uint256 positionId,
        externalEuint8  yearsExpExt,
        externalEuint8  eduLevelExt,
        externalEuint16 skillsMaskExt,
        externalEuint32 expSalaryExt,
        bytes calldata  proof
    ) external returns (ebool verdictCt) {
        Criteria storage c = _criteria[positionId];
        require(c.exists, "Position not found");

        // Progressive aggregation to keep stack shallow.
        // Each block has local variables that go out of scope immediately.
        ebool agg;

        // 1) yearsExp >= minExp
        {
            euint8 candExp = FHE.fromExternal(yearsExpExt, proof);
            agg = FHE.ge(candExp, c.minExp);
        }

        // 2) eduLevel >= minEdu
        {
            euint8 candEdu = FHE.fromExternal(eduLevelExt, proof);
            ebool eduOK = FHE.ge(candEdu, c.minEdu);
            agg = FHE.and(agg, eduOK);
        }

        // 3) (skillsMask & requiredSkills) == requiredSkills
        {
            euint16 candSkills = FHE.fromExternal(skillsMaskExt, proof);
            euint16 andMask = FHE.and(candSkills, c.requiredSkills);
            ebool skillOK = FHE.eq(andMask, c.requiredSkills);
            agg = FHE.and(agg, skillOK);
        }

        // 4) expectedSalary <= maxSalary
        {
            euint32 candSalary = FHE.fromExternal(expSalaryExt, proof);
            ebool salOK = FHE.le(candSalary, c.maxSalary);
            agg = FHE.and(agg, salOK);
        }

        // ACL + emit
        FHE.allow(agg, c.employer);
        FHE.allowThis(agg);

        emit ApplicationEvaluated(positionId, msg.sender, c.employer, FHE.toBytes32(agg));
        return agg;
    }

    /* ───────────────────────── Utilities ───────────────────────── */

    function version() external pure returns (string memory) {
        return "SecretResumeFilter/1.0.1";
    }
}
