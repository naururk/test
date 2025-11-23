// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * PRTierScoringFHE
 *
 * Anonymous scoring of PR contributions:
 * - User submits encrypted total score (e.g., off-chain aggregation of PRs/lines/reviews).
 * - Contract compares it against encrypted thresholds T1 < T2 < T3.
 * - Only the final tier information is public (as three public-decryptable flags: passT1, passT2, passT3).
 * - The user's raw encrypted score remains private (user can decrypt their own score via userDecrypt).
 *
 * Design notes:
 * - Uses Zama FHEVM official libs.
 * - No deprecated FHE APIs (no asEuint* etc).
 * - Avoids FHE ops in view functions; views only expose handles (bytes32).
 * - Public-decryptable outputs are made with FHE.makePubliclyDecryptable.
 * - Contract and user are allowed on stored ciphertexts (FHE.allowThis / FHE.allow).
 */

import {
  FHE,
  ebool,
  euint16,
  euint32,
  euint64,
  externalEuint16,
  externalEuint32,
  externalEuint64
} from "@fhevm/solidity/lib/FHE.sol";

import { ZamaEthereumConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract PRTierScoringFHE is ZamaEthereumConfig {
  address public owner;
  modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }

  constructor() {
    owner = msg.sender;
  }

  // --- Simple nonReentrant guard (future-proof if you add payable flows) ---
  uint256 private _locked = 1;
  modifier nonReentrant() {
    require(_locked == 1, "reentrancy");
    _locked = 2;
    _;
    _locked = 1;
  }

  // ===================== Encrypted Policy =====================
  // Thresholds for tiers; all are encrypted and not public:
  //   if score >= T1 -> tier >= 1
  //   if score >= T2 -> tier >= 2
  //   if score >= T3 -> tier >= 3
  //
  // Only the booleans (passT1, passT2, passT3) per user are made publicly decryptable.
  euint32 private eT1;
  euint32 private eT2;
  euint32 private eT3;

  event ThresholdsUpdated();

  /**
   * Owner sets encrypted thresholds.
   * Provide handles created off-chain with the Relayer SDK.
   */
  function setThresholds(
    externalEuint32 _T1,
    externalEuint32 _T2,
    externalEuint32 _T3,
    bytes calldata proof
  ) external onlyOwner {
    eT1 = FHE.fromExternal(_T1, proof);
    eT2 = FHE.fromExternal(_T2, proof);
    eT3 = FHE.fromExternal(_T3, proof);

    // Contract must be authorized to use them for comparisons.
    FHE.allowThis(eT1);
    FHE.allowThis(eT2);
    FHE.allowThis(eT3);

    emit ThresholdsUpdated();
  }

  // ===================== Applications / Scores =====================
  struct Application {
    address user;

    // Private encrypted score (user-only decrypt)
    euint32 eScore;

    // Publicly decryptable flags for tier >= 1,2,3
    ebool passT1;
    ebool passT2;
    ebool passT3;

    bool decided;
  }

  mapping(address => Application) private apps;

  event Scored(address indexed user, bytes32 passT1H, bytes32 passT2H, bytes32 passT3H);

  /**
   * User submits encrypted total score.
   * The contract computes public tier flags and makes them publicly decryptable.
   * Raw score stays private for the user (contract also keeps access).
   */
  function submitScore(
    externalEuint32 encScore,
    bytes calldata proof
  ) external nonReentrant {
    Application storage A = apps[msg.sender];

    // Ingest encrypted score
    euint32 s = FHE.fromExternal(encScore, proof);

    // Authorize contract + user (user to decrypt privately later)
    FHE.allowThis(s);
    FHE.allow(s, msg.sender);

    // Compare to encrypted thresholds
    ebool ge1 = FHE.ge(s, eT1);
    ebool ge2 = FHE.ge(s, eT2);
    ebool ge3 = FHE.ge(s, eT3);

    // Persist
    A.user   = msg.sender;
    A.eScore = s;
    A.passT1 = ge1;
    A.passT2 = ge2;
    A.passT3 = ge3;
    A.decided = true;

    // Allow contract to continue using stored ciphertexts
    FHE.allowThis(A.eScore);
    FHE.allowThis(A.passT1);
    FHE.allowThis(A.passT2);
    FHE.allowThis(A.passT3);

    // Make only the tier flags publicly decryptable (not the score)
    FHE.makePubliclyDecryptable(A.passT1);
    FHE.makePubliclyDecryptable(A.passT2);
    FHE.makePubliclyDecryptable(A.passT3);

    emit Scored(msg.sender, FHE.toBytes32(A.passT1), FHE.toBytes32(A.passT2), FHE.toBytes32(A.passT3));
  }

  // ===================== Getters (handles only) =====================
  // Views never do FHE ops; they only expose handles for Relayer decrypt flows.

  /**
   * Returns handles for:
   * - score (private; user can userDecrypt)
   * - three public-decryptable tier flags
   * - decided latch
   */
  function getMyHandles()
    external
    view
    returns (bytes32 scoreH, bytes32 passT1H, bytes32 passT2H, bytes32 passT3H, bool decided)
  {
    Application storage A = apps[msg.sender];
    return (FHE.toBytes32(A.eScore), FHE.toBytes32(A.passT1), FHE.toBytes32(A.passT2), FHE.toBytes32(A.passT3), A.decided);
  }

  /**
   * Public lookup of someone’s public tier flag handles (for publicDecrypt).
   * Frontend can compute tier = number of true flags among the three.
   */
  function getTierHandlesOf(address who)
    external
    view
    returns (bytes32 passT1H, bytes32 passT2H, bytes32 passT3H, bool decided)
  {
    Application storage A = apps[who];
    return (FHE.toBytes32(A.passT1), FHE.toBytes32(A.passT2), FHE.toBytes32(A.passT3), A.decided);
  }

  /**
   * Optional: score handle of other address (still private; only the user can decrypt via userDecrypt).
   * Provided for convenience if you want to display "you can decrypt only your own score".
   */
  function getScoreHandleOf(address who) external view returns (bytes32 scoreH, bool decided) {
    Application storage A = apps[who];
    return (FHE.toBytes32(A.eScore), A.decided);
  }

  // ===================== Ownership =====================
  function transferOwnership(address newOwner) external onlyOwner {
    require(newOwner != address(0), "zero owner");
    owner = newOwner;
  }
}
