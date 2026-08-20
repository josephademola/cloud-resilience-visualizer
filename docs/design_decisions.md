# Design decisions

This document records why Cloud Resilience Visualizer (CRV) is built
the way it is. Each entry covers one decision: what was decided, what
else was considered, why the chosen option won, and roughly when it
was decided. New architectural decisions get a new entry here in the
same commit as the code that implements them.

---

## 1. Static JSON framework mappings, not AI-generated

Decision | Finding types are mapped to framework requirements (NIS2, NCSC CAF, MITRE ATT&CK, Cyber Essentials) through hand-authored JSON files, each with a documented rationale.
Alternatives considered | Generating mappings at scan time with an LLM, or generating them once and committing the output without a human review step.
Rationale | Compliance evidence has to be defensible to a regulator or auditor. "The model decided" is not an auditable justification. Static mappings can be reviewed, corrected, and cited line by line.
Date | ~2026-07-02, rationale notes added 2026-07-13

## 2. Fail-closed semantics for protection signals

Decision | For protection signals (`encryption_enabled`, `public_access_block_fully_enabled`), a missing value is treated as "not protected" and flagged. For detection signals (`is_public_via_acl`), a missing value is treated as "not detected" and not flagged.
Alternatives considered | Fail-open everywhere (missing data assumed safe), or raising an error when a field is absent.
Rationale | Assuming safety in the absence of evidence is the wrong default for a security tool. This matches how established CSPM tools such as Prowler and ScoutSuite treat incomplete data.
Date | ~2026-07-02

## 3. Content separated from code

Decision | Finding text (title, severity, description, remediation) lives in `finding_content.json`. Framework references live in the mapping JSON files. Scanner Python files contain only detection logic, no strings.
Alternatives considered | Inlining finding text as string literals in each scanner function.
Rationale | Someone without Python knowledge (a security writer, a compliance reviewer) can correct or extend finding text without touching code, and without needing a code review from an engineer to fix a typo.
Date | 2026-07-13

## 4. One function per scanner rule

Decision | Each detection rule is a small function taking a resource node dict and returning a `Finding` or `None`. The top-level `scan_*` function only loops over nodes and dispatches to a tuple of rule functions.
Alternatives considered | One monolithic function per resource type containing all rule logic as sequential if-statements.
Rationale | Each rule is independently testable, independently readable, and addable without touching existing rules. A regression in one rule can't silently affect another.
Date | 2026-07-02

## 5. Mock data shaped like live boto3 responses

Decision | `mock_aws.json` mirrors the exact structure of real boto3 API responses (method names, nesting, key casing), rather than a simplified custom shape.
Alternatives considered | A simpler, CRV-specific mock schema that would need a translation step before hitting the normaliser.
Rationale | The normaliser, scanner, and everything downstream can be built and tested entirely against mock data, then pointed at a real AWS account later by adding one client file. This paid off directly: live AWS support (`aws_client.py`, `USE_LIVE_AWS=true`) was a data-source swap, not a rewrite.
Date | mock data 2026-06-14, live AWS swap 2026-07-28

## 6. Rejected AI-generated framework mappings, considered twice

Decision | Framework mappings are never generated or auto-suggested by an LLM, even as a draft to be reviewed.
Alternatives considered | Using an LLM to draft mappings and having a human review and correct them before committing.
Rationale | This was reconsidered once during the mapping audit and rejected again: even a "draft plus review" workflow tends to anchor the reviewer on the model's framing rather than starting from the framework text. The one mapping that needed correcting during audit (`S3_PUBLIC_ACCESS_BLOCK_DISABLED`, originally mapped to MITRE T1078.004, corrected to T1580) was caught precisely because it had been reasoned through and documented by hand, with the wrong reasoning visible and correctable in `audit_notes`. A generated mapping without that trail would have been harder to catch and harder to justify removing.
Date | 2026-07-13

## 7. SHA-256 integrity hash on evidence records

Decision | Every evidence record includes a SHA-256 hash of the input topology and a SHA-256 integrity hash over the full record (findings summary, IAM identity, timestamp, tool version).
Alternatives considered | Returning findings and metadata without any hash, relying on the API response itself as the record.
Rationale | Regulatory audit trails need tamper evidence, not just a data export. Any post-hoc edit to a stored evidence record changes its hash, making silent modification detectable.
Date | 2026-07-29

## 8. Tag-based target selection (Project=X) instead of hardcoded account scan

Decision | Scans can be scoped to resources carrying a specific tag (e.g. `Project=ShiftCommute`), discovered via the AWS Resource Groups Tagging API, instead of always scanning every resource in the account.
Alternatives considered | Scanning the whole account on every run and filtering findings after the fact; or hardcoding a second, ShiftCommute-specific scan path alongside the existing one.
Rationale | A whole-account scan doesn't distinguish between projects sharing an AWS account, and a hardcoded second path would duplicate the scanner/normaliser/compliance pipeline instead of reusing it. Tag-based scoping keeps CRV as a single generic pipeline that can audit any tagged project, ShiftCommute included, without new architecture.
Date | Decided 2026-08-20 as part of Phase 9a planning. Not yet implemented; tracked as Phase 9a Feature 1.

## 9. KMS rotation scanner scopes to customer-managed keys only

Decision | KMS scanner scopes to customer-managed keys only (`KeyManager == "CUSTOMER"`).
Alternatives considered | Scan all KMS keys including AWS-managed.
Rationale | AWS-managed keys rotate automatically; the account owner has no control over that setting. Flagging them would produce false positives that a real auditor would reject. The rule applies only where the control is the owner's responsibility.
Date | 2026-08-20, part of Phase 9a Feature 3 (kms_scanner.py)

## 10. Age-based checks depend on wall-clock time, confined to the scanner layer

Decision | `IAM_ACCESS_KEY_AGE_EXCEEDS_90_DAYS` compares each active access key's creation date to the current time at scan time. `datetime.now()` is used only inside the scanner rule function, never in `aws_normalizer.py`.
Alternatives considered | Avoiding wall-clock time entirely (not possible for an age-based control — every real CSPM tool, including Prowler and ScoutSuite, has this same property); or computing the age in the normaliser instead of the scanner.
Rationale | This is a deliberate, narrow exception to decision #5 (deterministic output everywhere). "Same input, same output" holds for every other rule in this codebase because nothing else depends on the current date; an age-based check cannot make that claim without becoming useless, since a key that was fine yesterday is correctly flagged today. The honest version of the determinism principle here is "same input, same day, same output" — determinism within a scan run, not invariance across calendar time. Confining `datetime.now()` to the scanner rule, rather than letting it leak into the normaliser, keeps `_normalize_iam_users()` a pure function of its input; only the rule that is inherently time-relative reaches for the clock.
Date | 2026-08-20, part of Phase 9a Feature 3 (iam_scanner.py)

---

*Note: an earlier draft of this document also listed a decision to
reject WAF integration into the CSPM pipeline. That entry has been
removed because there is no evidence for it in the codebase or commit
history, only an empty, never-populated `backend/app/waf/` skeleton
folder dating back to the initial project scaffold, since removed.
Documenting an undecided rejection as fact would have failed the same
auditability standard this document exists to uphold.*
