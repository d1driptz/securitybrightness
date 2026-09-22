# From authorization foundation to security platform

This sequence implements the expanded product vision without treating existing demonstrations as earned protection claims. Baseline for the inspection: efc3100 (187 passing core tests, explicit-unlock persistence and final revalidation).

## Evidence from the existing scanner

The repository's single index.html uses FileReader.readAsText on a user-selected file and 20 regular-expression rules. It groups matches for provider-token shapes, generic credentials, personal-data labels, addresses, prompt-injection phrases, tool words and internal-looking URLs. It does not parse executable formats, validate live credentials, use a threat-intelligence feed/model, observe running processes or mediate their actions. No network upload, external script or browser storage call appears in the inspected repository page. This describes that source, not independently deployed hosting or future dependencies.

The original title says AI Security Scanner, but no AI model is present. This is limited text-pattern analysis, not malware detection, antivirus protection, vulnerability assessment or proof of safety. A match can be an example/benign mention; absence can reflect unsupported formats, encodings, obfuscation or incomplete rules.

Inspection found specific migration blockers:

- A special case deletes text from the first `patterns = [` through `];`. An input can hide findings there, and later match offsets no longer refer to original text.
- Raw matched strings can expose secrets in the results view. HTML escaping helps markup safety but does not redact secrets.
- The file input accept hint is not validation. There is no file-size/work bound, and analysis runs on the main browser thread.
- Counts are rule groups and at most five retained examples, not necessarily all occurrences. The displayed time measures file reading before analysis, not full analysis time.
- The Mark as fixed button neither repairs nor verifies a file. Its handler passes a nonexistent index instead of the encoded rule message, so dismissal is also broken.
- Generic keyword severities are not calibrated threat probabilities. A blanket no-findings message must not become a safety claim.

The bundled SoulScript archive was inventoried without extracting or running it. Its separate agent project and stored assets are not a scanner dependency or authorization enforcement component. Do not execute or import bundled models/pickles/code to manufacture security functionality.

## Evidence from the desktop/core

The Tk desktop runs trusted operator UI on its main thread and a single HTTP worker. Credential-free review messages and registry summaries separate display from application credentials. The core authorizes only. Optional SQLite authority storage starts inactive and needs exact-version human unlock. Final registry/activation checks prevent stale review approval. These are useful foundations, not process isolation: all Python components still share prototype A's trusted OS session.

At the inspection baseline, gaps included synchronous request blocking, partial audit coverage, code-defined policy, broad scopes, no expiry/one-shot semantics, no downstream operation binding, no strong human identity or isolated Windows authority component. Storage inherited directory protections without rollback protection. The GUI then had no file-review panel, history, assistant or device monitoring. The implemented file-review follow-up is described below; the other gaps remain.

## Dependency-based development sequence

History follow-up: a read-only [decision-history view](decision-history.md) now projects bounded summaries from the existing audit file. This advances visibility under step 4 without changing retention, storage, lifecycle coverage or authority. Comprehensive security history and justified integrity guarantees remain planned.

Acquisition follow-up: the desktop now reads its one explicitly selected file in a fixed helper with bounded pipes, deadline/cancellation and cleanup, then analyzes the returned snapshot in the separate analyzer. This replaces the earlier in-process acquisition limitation without adding privileges or claiming atomic path confinement/OS sandboxing. Direct low-level acquisition remains synchronous for trusted callers; the desktop uses the helper.

The desktop now offers explicit selection of one regular file for three supported private-key-header patterns. It uses bounded helpers and redacted evidence, with no authority objects passed to processing. Broader detection, stronger OS isolation, comprehensive security history, device monitoring and the assistant remain planned. See [the contract guide](file-security.md) for current behavior and limits.

The first scanner correction batch removes the content exclusion, preserves original locations, withholds matched values, counts every rule occurrence while retaining at most five locations per group, and repairs dismissal without claiming remediation. Selection is limited to .txt/.log/.js files up to 1 MiB; oversized decoded content and NUL-containing content are rejected. Older asynchronous read callbacks cannot overwrite a newer scan. Private-key headers now match at ordinary line starts. Timing includes reading and analysis; the page describes heuristic review rather than an AI or malware verdict.

Run `node tests/test_web_scanner.js` for synthetic regression fixtures using Node's built-in test harness. These exercise the actual page script in a minimal DOM substitute, not a browser layout/accessibility audit or measured detection evaluation. The original five regression fixtures failed before correction. Additional cases cover private-key headers, stale reads and rejected decoded content.

The size cap is not a CPU deadline. Regular expressions still run on the browser main thread, binary detection is incomplete, decoding is not strict, and extensions do not establish file type. Rules have false positives and false negatives; priority is not calibrated impact or confidence. Withholding match text does not erase source bytes from browser memory or conceal filenames. No uploads, file modification, quarantine or execution was added. Worker isolation, structured evidence and evaluated coverage remain prerequisites for desktop reuse.

The sequence below distinguishes this first correction from the remaining planned capabilities:

Step 2 has a narrow implementation: the [supplied-content contract](file-security.md) analyzes immutable UTF-8 bytes for three exact private-key header markers. It returns versioned redacted locations/counts, exact-byte identity and explicit rejection/limitations without importing core authority. The desktop uses this contract; full browser-rule parity and measured broader coverage remain unimplemented.

Consumer-side bounded JSON/schema validation is implemented and used on worker output, including caller-owned digest/length binding and rejection of authority/source fields. It does not prove provenance or that an analyzer reported truthfully.

Fixed Python helpers transport the selected path or supplied bytes using bounded pipes, with one active helper per parent, deadlines and failure cleanup. They do not accept commands or execute samples. This is a tested availability boundary, not a restricted-account sandbox or protection against hostile same-user code. Desktop acquisition/presentation is implemented; broader measured coverage remains a prerequisite for broader claims.

1. Correct the existing scanner's narrow behavior and claims. Remove content exclusions, retain correct positions, distinguish occurrence/group/display counts, redact matched values, bound inputs, and make dismissal clearly non-remediation. Use synthetic adversarial fixtures; do not claim malware coverage from these tests.
2. Define an analysis-only File Security contract before desktop reuse. Inputs are explicitly supplied bounded content, not arbitrary execution instructions. Outputs carry rule/version, artifact identity, evidence location, redacted finding, confidence/limitations and incomplete/error status. The analyzer receives no registry, credentials, operator callback or administrative authority. No network or sample execution; no deletion/quarantine/remediation.
3. Build measured text-analysis capability with positive/negative/obfuscated/large/malformed corpora and explicit timeout/memory/encoding behavior. Separate analysis workers from the UI for availability, without claiming that a same-user process is a strong sandbox. Packaging it in the desktop follows contract/evidence tests, not a cosmetic Scan button. Binary/archive/document analyzers need separate parser and hostile-input threat models.
4. Extend security evidence/history across authority changes, reviews, failures and analysis. Define transaction, retention, redaction, provenance and recovery behavior before claiming trustworthy proof. Add a human-readable history view. Avoid silently weakening revocation through store restore or conflating AI assertions with authoritative facts.
5. Add richer versioned action/effect contracts and constrained/lifetime grants in compatible increments. Keep current authority separate from proposal data and revalidate immediately before final authorization. Unimplemented expiry/one-shot/resource constraints must fail closed, not fall back to broad authority.
6. Build a least-privilege Security Assistant over approved read interfaces and structured proposals. Start with deterministic navigation/explanations rather than granting a chatbot admin credentials. Conversational intent cannot unlock, approve or execute. External model/data-transfer dependencies require owner review.
7. Design Device Security separately from integrated authorization. Label observed, integrated and genuinely enforced coverage. Choose narrowly justified signals and obtain evidence for any vulnerability/detection claim. Privileged monitoring, OS-level mediation and invasive collection require owner decisions before implementation.
8. Implement B only under its own approved threat model: isolated Windows human authority, authenticated IPC, secure custody and adversarial evidence against same-user attackers. Keep the core/provider model and application API stable. An execution/capability broker remains a separate decision; none is implied by monitoring, File Security or B.

Default to small, defensible capabilities. Each security claim needs a threat model, implementation evidence, adversarial evaluation and eventual independent assessment. Lifecycle persistence, scanner results and an SDK badge do not make arbitrary third-party applications controlled. Trust is not authority, including inside SecurityBrightness.
