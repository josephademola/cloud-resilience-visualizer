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

Decision | Scans can be scoped to resources carrying a specific tag (e.g. `Project=<tag-value>`), discovered via the AWS Resource Groups Tagging API, instead of always scanning every resource in the account.
Alternatives considered | Scanning the whole account on every run and filtering findings after the fact; or hardcoding a second, client-specific scan path alongside the existing one.
Rationale | A whole-account scan doesn't distinguish between projects sharing an AWS account, and a hardcoded second path would duplicate the scanner/normaliser/compliance pipeline instead of reusing it. Tag-based scoping keeps CRV as a single generic pipeline that can audit any tagged project, a confidential client engagement included, without new architecture.
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

## 11. Client-confidential mapping files are gitignored, fail-closed by scope, and never named in the repo

Decision | `confidential_controls.json` (a confidential client's internal control catalogue, built for Phase 9a Feature 2) is not committed to this repo. `app/mappings/loader.py` skips a missing mapping file rather than crashing. In code, findings only carry that framework's references, and the compliance dashboard only shows its section, when the scan is explicitly scoped to the tagged project, gated by a keyword parameter (`include_confidential`) that defaults to `False`. Which tag value unlocks it is read from a `CONFIDENTIAL_PROJECT_TAG` environment variable, set per-deployment and never committed, rather than hardcoded — so the client's actual name never needs to appear anywhere in this repo's source, tests, or history.
Alternatives considered | Committing the file and relying on scope-filtering alone; committing it but documenting it as "not for public use"; keeping the fail-open default (include unless told not to) that an earlier draft of this fix briefly had before being caught and corrected; hardcoding the real client's name as the scope-matching string (the first version of this fix did exactly that, and repeated the mistake this decision now corrects).
Rationale | This corrects two real mistakes, not hypotheticals. First: the mapping file itself was committed in Feature 2's initial implementation and was live on the public repo and the deployed API for three days before being caught, returning a client's internal control mappings on every scan regardless of who or what was actually being audited. Second: the first fix for that, while it stopped the file itself from being exposed, still named the client explicitly in commit messages, docs, and code identifiers — which is its own disclosure, since a public repo stating "client X's confidential control catalogue was exposed" reveals the client relationship even without the file. Neither fix is retroactive: untracking a file, or rewriting history to remove a name, stops it spreading further but does not remove it from anyone who already cloned the repo, forked it, or hit the live API/viewed the commit during the window it was exposed — an important limit to be honest about, not something either fix can undo. Fail-closed by default matters as much as the gitignore and the generic naming: a caller (present or future) that forgets to pass the scope flag gets the safe behaviour, the same discipline this project already applies to every protection signal (decision #2, fail-closed semantics). A client's confidential control catalogue existing in the tool at all, or that client's identity being derivable from the tool's source, is only correct when that client's own scan asked for it.
Date | 2026-08-23, prompted by the user catching the file exposure 3 days after Feature 2 shipped; naming disclosure caught and corrected the same day

## 12. Resource Groups Tagging API is queried on every scan, not just scoped ones

Decision | `aws_client.py` now calls the Resource Groups Tagging API unconditionally on every live scan. Previously it was only called when a `project_tag` was given, since an unscoped scan had no use for it.
Alternatives considered | Keeping the call gated on `project_tag`, and only computing tag-presence data for scoped scans; adding a separate, opt-in flag to request tag-presence checking specifically.
Rationale | `RESOURCE_MISSING_TAGS` (tagging_scanner.py) exists to catch a real blind spot in tag-based discovery: a resource nobody remembered to tag is invisible to a scoped scan, indistinguishable from a resource that doesn't exist at all. That finding is only meaningful on an *unscoped* scan — a scoped scan already filters every taggable node down to ones that matched the requested tag, so they'd trivially all appear tagged regardless. Making the check possible therefore means always having the account's full tag picture, not just the scoped slice. The extra API call's cost is one additional Resource Groups Tagging API request per scan; judged worth it for closing a real discovery gap rather than adding a second opt-in code path that most callers would forget to enable.
Date | 2026-08-28, part of the Phase 1 CSPM gap-analysis build-out (tagging_scanner.py)

## 13. CIS AWS Foundations Benchmark mapping deliberately leaves 12 of 25 finding types unmapped

Decision | `cis_aws_foundations.json` maps 13 of this project's 25 finding types to a real CIS v3.0.0 requirement number. The other 12 have no top-level entry in the file at all — the same "absent, not an empty placeholder" convention `confidential_controls.json` already established for `RESOURCE_MISSING_TAGS` and `GOV-01` — with an `audit_notes` entry for each one explaining specifically why no CIS control applies.
Alternatives considered | Mapping every finding type to *some* CIS requirement regardless of fit (e.g. folding S3 encryption/versioning/logging/lifecycle findings into the nearest loosely-related control), which every other framework file in this project explicitly avoids doing; or omitting CIS entirely until every finding type could be cleanly mapped.
Rationale | CIS AWS Foundations Benchmark is a narrow, "foundational quick-wins" baseline — it covers root/IAM hygiene, CloudTrail, KMS rotation, and a handful of S3 controls (block public access, SSL enforcement), but was never designed to cover encryption-at-rest, versioning, access logging, lifecycle management, KMS key policy content, key aliasing, or resource tagging for general-purpose resources. Forcing a mapping where none genuinely exists would misrepresent what passing CIS actually certifies — a compliance officer reading "0 CIS findings" should not conclude the environment has no encryption or versioning gaps, when CIS simply never checked for them. The gap itself is documented as a real, useful fact (see the file's own `mapping_rationale`), not hidden as a coverage failure. Two IAM findings (`IAM_USER_ADMIN_POLICY_ATTACHED`, `IAM_USER_POLICY_GRANTS_WILDCARD_ACTION`) are mapped with an explicit imperfect-fit caveat (CIS 1.15's actual concern is direct-attachment manageability, not excessive privilege specifically) rather than silently presented as clean matches — the same "document the compromise rather than dress it up" discipline `mitre_attack.json` already applies to its own forced mappings.
Date | 2026-09-01, CSPM gap-analysis follow-up (S3 AuthenticatedUsers ACL coverage + CIS benchmark mapping)

---

*Note: an earlier draft of this document also listed a decision to
reject WAF integration into the CSPM pipeline. That entry has been
removed because there is no evidence for it in the codebase or commit
history, only an empty, never-populated `backend/app/waf/` skeleton
folder dating back to the initial project scaffold, since removed.
Documenting an undecided rejection as fact would have failed the same
auditability standard this document exists to uphold.*
