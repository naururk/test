# Secret Resume Filter · Zama FHEVM

Privacy-first recruiting on-chain. Candidates submit **encrypted** résumé attributes; the contract returns only a single **encrypted verdict** (FIT / NO FIT). Employers decrypt the verdict with **userDecrypt** via Zama’s Relayer SDK, while raw inputs and criteria remain private.

> **Network**: Sepolia
> **Contract (deployed)**: `0x12D716b26D896adC8994eFe4b36f11EF37158D96`
> **Relayer SDK**: `@zama-fhe/relayer-sdk` v0.2.0
> **Solidity**: 0.8.24 with `viaIR: true`, optimizer enabled

---

## Overview

**Secret Resume Filter** is a minimal, production-style FHEVM dApp:

* **Employers** create positions and upload **encrypted criteria** (min experience, min education, required skills bitmask, max salary).
* **Candidates** submit **encrypted applications** (same fields, encrypted locally in the browser).
* The contract evaluates everything **homomorphically** and emits a handle for an **encrypted verdict**.
* **Only the employer** gets decryption rights for the verdict (user-level EIP‑712 auth with Relayer SDK).

This lets teams pre-screen candidates without revealing sensitive compensation expectations or personal data on-chain.

---

## Core Features

* 🔒 Fully encrypted inputs & criteria (Zama FHE Solidity lib).
* ✅ Binary result only: **FIT / NO FIT** (as `ebool`).
* 👤 Access control with `FHE.allow` — employer-only decryption.
* 🧩 Bitmask skill check: `(skills & required) == required`.
* 🔧 Clean separation of roles (Owner → creates positions, Employer → manages criteria, Candidate → applies).
* ⚙️ Works with Relayer SDK v0.2.0 (WASM workers enabled).

---

## Smart Contract

* File: `contracts/SecretResumeFilter.sol`
* Inherits: `SepoliaConfig` from `@fhevm/solidity`
* Uses only official Zama Solidity library: `@fhevm/solidity/lib/FHE.sol`

### Main storage

```solidity
struct Criteria {
  euint8  minExp;          // candidate.yearsExp >= minExp
  euint8  minEdu;          // candidate.eduLevel >= minEdu
  euint16 requiredSkills;  // (skills & required) == required
  euint32 maxSalary;       // candidate.expSalary <= maxSalary
  address employer;        // decrypt rights holder
  bool    exists;
}
```

### Key functions

* `createPosition(uint256 positionId, address employer)` — owner creates/assigns a position to an employer.
* `setCriteriaEncrypted(positionId, minExp, minEdu, reqSkills, maxSalary, proof)` — employer sets **encrypted** criteria via Relayer SDK.
* `setCriteriaPlain(positionId, ...)` — dev helper; converts clear values to encrypted on-chain (avoid in prod).
* `makeCriteriaPublic(positionId)` — demo helper to mark criteria publicly decryptable.
* `getCriteriaHandles(positionId)` — returns `bytes32` handles for off-chain audits.
* `evaluateApplication(positionId, yearsExp, eduLevel, skillsMask, expSalary, proof)` — returns encrypted `ebool` verdict; grants decryption right to the employer.

> The `evaluateApplication` implementation aggregates conditions progressively inside scoped blocks to avoid `Stack too deep` and keeps gas reasonable.

### Events

* `PositionCreated(positionId, employer)`
* `CriteriaUpdated(positionId, minExpH, minEduH, requiredSkillsH, maxSalaryH)`
* `ApplicationEvaluated(positionId, candidate, employer, verdictHandle)`

---

## Frontend

* Single-file app
* Location: **`frontend/public/index.html`** (no build tools required; pure ESM and CDN).
* Tech: Ethers v6 + Relayer SDK v0.2.0.
* Design: neon-glass dark UI with skill chips, event scanning & one-click decrypt.

**What it does:**

1. Connects wallet and initializes Relayer SDK (`initSDK()` → `createInstance(...)`).
2. Employer flow: create position → set encrypted criteria → scan `ApplicationEvaluated` → **userDecrypt** verdict.
3. Candidate flow: pick position → encrypt 4 fields → submit → employer later decrypts the verdict.


## Security

* This project demonstrates encrypted comparisons using FHEVM. Always audit before production use.
* Keep Relayer SDK versions pinned (here: v0.2.0).
* Never log plaintext candidate data; UI encrypts client-side prior to any chain call.

---

## License

MIT — see `LICENSE` file.
