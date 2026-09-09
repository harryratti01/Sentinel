# Sentinel Development State & Engineering Specification

## 1. Project Identity

Project name: Sentinel

Platform target: Windows

Primary language: Python

Primary purpose:

Sentinel is a Windows file-integrity and security monitoring system designed to establish an explicitly trusted filesystem state and continuously determine whether protected files or directories have changed relative to that trusted state.

Sentinel is not intended to merely report raw filesystem events.

The core security concept is:

```
TRUSTED STATE
    |
    v
OBSERVE CURRENT STATE
    |
    v
COMPARE
    |
    v
DETERMINE WHAT CHANGED
    |
    v
PRESERVE EVIDENCE
    |
    v
GENERATE A SUPPORTED FINDING
    |
    v
EXPLAIN THE FINDING
```

Long-term vision:

```
User selects file or directory
    |
    v
Sentinel inspects target
    |
    v
User explicitly confirms target as trusted
    |
    v
Sentinel creates immutable trusted baseline
    |
    v
Target becomes ACTIVE protected target
    |
    v
Sentinel automatically monitors ACTIVE targets
    |
    v
Filesystem changes are captured
    |
    v
Current state is reconciled against trusted baseline
    |
    v
Security findings are generated
    |
    v
Evidence is persisted
    |
    v
Sentinel maintains chronological security history
    |
    v
User receives meaningful alerts, reports, and investigation tools
    |
    v
Sentinel eventually operates as a Windows background service
```

The project must prioritize correctness, evidence preservation, explainability, and architectural clarity before production hardening or advanced features.

---

# 2. Core Security Principle

Sentinel must distinguish between:

```
RAW OBSERVATION
RECONCILIATION RESULT
INTERPRETATION
```

These are NOT interchangeable.

A raw filesystem event describes what the operating system reported.

A reconciliation finding describes what Sentinel determined after comparing the current filesystem state against the trusted baseline.

An interpretation explains what Sentinel can reasonably conclude from the available evidence.

Therefore:

```
RAW EVENT != FINDING
FINDING != INTERPRETATION
```

Never discard lower-level evidence merely because a higher-level finding exists.

Never fabricate an interpretation that is not supported by evidence.

Example:

If the filesystem reports:

```
MODIFIED
```

and reconciliation determines:

```
current content differs from trusted baseline
```

Sentinel may generate:

```
MODIFIED
```

If the filesystem reports a metadata-affecting change but current content is identical to baseline, Sentinel may determine:

```
METADATA_CHANGED
```

However, Sentinel must not automatically claim:

```
"The file was modified and restored"
```

unless the available event/history evidence actually supports that sequence.

---

# 3. Development Philosophy

Build Sentinel incrementally.

Use:

```
DISCOVER
    |
    v
PLAN
    |
    v
IMPLEMENT
    |
    v
TEST
    |
    v
REVIEW
    |
    v
FIX
    |
    v
TEST AGAIN
    |
    v
PASS -> STOP
    |
    v
FAIL -> ITERATE
```

Correctness and architecture come before feature quantity.

Do not attempt to make Sentinel production-ready prematurely.

Production hardening, Windows service behavior, startup behavior, security hardening, performance optimization, recovery behavior, advanced threat detection, and deployment concerns belong to later milestones unless explicitly brought forward.

Prefer small, coherent changes.

Reuse existing working functionality.

Do not rewrite functioning components merely because a different implementation appears cleaner.

---

# 4. Current Repository Architecture

The current repository contains the following important areas:

```
core/
    database.py
    cli.py
    acceptance.py
    monitoring.py
    watcher / filesystem functionality
    reconciliation functionality
    protection functionality
    processing functionality

tests/
    test_workflow.py
    test_reconciliation.py
    test_protection.py
    test_monitoring.py

data/
    sentinel.db

.codex/
    sentinel_development.md
```

The exact repository contents must always be inspected before making assumptions.

If a file/function/module name differs from this document, inspect the actual repository and update this document only when the architecture has genuinely changed.

Do not invent modules that do not exist.

---

# 5. Major Domain Concepts

## 5.1 Protected Target

A protected target represents a file or directory that Sentinel is responsible for monitoring.

Target types currently supported:

```
FILE
DIRECTORY
```

Target states currently include:

```
ACTIVE
DISABLED
```

An ACTIVE target is eligible for automatic monitoring.

A DISABLED target must not be monitored by the automatic monitoring coordinator.

---

## 5.2 Trusted Baseline

A trusted baseline represents the filesystem state explicitly accepted by the user as trusted.

The baseline is created from the target's state at protection time.

The baseline is security-sensitive.

IMPORTANT:

The baseline must not be silently replaced when the protected filesystem changes.

A modified file does NOT automatically become the new trusted state.

Rebaseline behavior is a future explicit feature.

---

## 5.3 Baseline File

A baseline file represents the trusted state of an individual file within a protected target.

Relevant baseline information may include:

* file identity
* path
* size
* timestamps
* metadata
* SHA-256 content hash
* associated baseline
* other evidence already supported by the existing schema

The exact current schema must be inspected before modifying it.

---

## 5.4 Filesystem Event

A filesystem event is an observation reported by the filesystem watcher.

Current supported event concepts include:

```
CREATED
MODIFIED
MOVED
DELETED
```

Events may contain:

* timestamp
* event type
* path
* old path
* new path
* other watcher evidence

Raw events should remain distinguishable from reconciled findings.

---

## 5.5 Finding

A finding is Sentinel's security-relevant conclusion after reconciliation.

Current finding types validated during development include:

```
CREATED
MODIFIED
RENAMED
MOVED
DELETED
MOVED_RENAMED_AND_MODIFIED
RENAMED_AND_MODIFIED
MOVED_RENAMED
METADATA_CHANGED
DELETED_AND_RECREATED_DIFFERENT
DELETED_AND_RECREATED_IDENTICAL
AMBIGUOUS_IDENTICAL_CONTENT
```

The exact set of finding types may evolve.

Do not add a new finding type merely to make output look nicer.

A new finding type must have a clear semantic definition and tests.

---

# 6. Current Reconciliation Philosophy

Sentinel's reconciliation system compares:

```
TRUSTED BASELINE
        vs.
CURRENT FILESYSTEM STATE
```

It attempts to determine meaningful differences such as:

* content changes
* metadata changes
* creation
* deletion
* rename
* movement
* compound operations
* delete/recreate behavior
* ambiguous identity situations

The reconciliation engine should remain evidence-driven.

A difference from baseline does not necessarily mean malicious behavior.

Sentinel should report what it can prove, not speculate about attacker intent.

---

# 7. File Identity

File identity is important because path alone is insufficient to determine whether a file is the same logical file after rename or movement.

Windows filesystem identity behavior has already been tested.

The implementation must preserve existing Windows-aware identity behavior.

Do not assume Unix filesystem semantics are identical to Windows semantics.

Do not identify a file solely by its current path when the existing architecture provides stronger identity evidence.

---

# 8. Protection Workflow

Current intended workflow:

```
protect <path>
    |
    v
validate target
    |
    v
inspect target
    |
    v
show summary
    |
    v
request explicit user confirmation
    |
    v
create trusted baseline
    |
    v
create protected target
    |
    v
associate target with baseline
    |
    v
target becomes ACTIVE
```

Protection behavior already includes:

* FILE targets
* DIRECTORY targets
* explicit confirmation
* duplicate protection prevention
* Windows path normalization
* missing target rejection
* empty-directory handling
* nested file handling
* symlink/junction rejection
* transactional rollback
* baseline association

Do not unnecessarily rewrite this functionality.

---

# 9. Automatic Monitoring Architecture

Milestone 5 introduced automatic monitoring of ACTIVE protected targets.

Current intended architecture:

```
ACTIVE protected targets
        |
        v
monitoring coordinator
        |
        v
one watcher per target
        |
        v
filesystem event
        |
        v
debounce / normalize
        |
        v
reconcile against immutable baseline
        |
        v
generate finding
        |
        v
persist finding
        |
        v
continue monitoring
```

The user must NOT need to manually start a separate watcher for every protected target.

The monitoring process discovers ACTIVE targets.

Disabled/unprotected targets must be excluded.

Duplicate watchers for the same target must not be created.

Multiple protected targets must remain independent.

Monitoring must continue after individual findings.

Monitoring must shut down cleanly.

---

# 10. Milestone 5 Completion

Milestone 5:

```
Automatic Monitoring of ACTIVE Protected Targets
```

Status:

```
COMPLETE
```

Implemented:

* ACTIVE target discovery
* baseline loading
* automatic watcher creation
* one watcher per active target
* recursive directory monitoring
* event handling
* event debouncing
* reconciliation
* finding generation
* finding persistence
* continued monitoring
* clean shutdown
* CLI monitor command
* monitor acceptance demonstration
* real filesystem monitoring tests

Milestone 5 verification:

```
Full automated suite:
14 tests passed
```

Manual acceptance testing was also performed against:

```
E:\Sentinel\system_test
```

The manual testing demonstrated live findings and continued monitoring.

The temporary manual testing directory was removed before the milestone commit.

Milestone 5 was committed after:

```
git diff --check
git diff --cached --check
staged-file review
successful test verification
```

No automatic commit/push behavior is permitted for future milestones.

---

# 11. Milestone 5 Manual Testing Findings

The following issues were discovered during real filesystem testing.

These findings are IMPORTANT and must remain documented.

They are not to be forgotten merely because the automated suite passes.

## Issue A - METADATA_CHANGED explanation is too vague

Observed behavior:

A file's content was restored to its original content, but metadata such as modification time differed.

Sentinel generated:

```
METADATA_CHANGED
```

The finding is technically consistent with the current baseline-vs-current reconciliation model.

However, the user-facing explanation is insufficient.

The user cannot immediately determine:

* which metadata changed
* whether content changed
* whether the file was previously modified
* whether the file was subsequently restored

Future interpretation must make this distinction explicit.

Do not claim "restored" unless history/evidence supports it.

---

## Issue B - Baseline-state finding can look like the latest operation

Observed sequence:

```
important.txt
    |
    v
important-renamed.txt
    |
    v
content restored / changed back
```

Sentinel subsequently reported:

```
RENAMED
```

This is understandable under the current reconciliation model because the current path still differs from the baseline path.

However:

```
current state != latest operation
```

A current finding of RENAMED means:

```
"The current file is located at a different path from the trusted baseline path."
```

It does NOT necessarily mean:

```
"The most recent filesystem operation was a rename."
```

Future history/interpretation must preserve this distinction.

Do not damage reconciliation correctness merely to make a finding label appear more intuitive.

---

## Issue C - previous_path represents baseline relationship, not full history

Observed sequence:

```
important.txt
    |
    v
important-renamed.txt
    |
    v
moved-important.txt
    |
    v
archive\moved-important.txt
```

Current finding records may contain:

```
previous_path = important.txt
```

This is useful as a baseline relationship but is not a complete chronological path history.

Future history must support:

```
important.txt
    ->
important-renamed.txt
    ->
moved-important.txt
    ->
archive\moved-important.txt
```

Do not reinterpret the existing previous_path field as a complete event history.

---

## Issue D - No persistent chronological file history yet

Current Sentinel can detect and persist findings, but it does not yet provide a proper chronological lifecycle view for a protected file.

Future capability should allow Sentinel to answer:

```
What happened?
When did it happen?
What path was the file at?
What changed?
What is its current state?
Does its current content match the trusted baseline?
What can Sentinel confidently conclude?
```

This is a major motivation for Milestone 6.

---

# 12. Important Architectural Distinction: Current State vs History

This distinction must remain explicit.

Reconciliation answers:

```
"How does the current state differ from the trusted baseline?"
```

History answers:

```
"What happened over time?"
```

These are different questions.

Example:

Current state:

```
file path differs from baseline
content matches baseline
metadata differs from baseline
```

Possible current findings:

```
RENAMED
METADATA_CHANGED
```

History may additionally show:

```
MODIFIED
RESTORED
RENAMED
```

Do not collapse these concepts into one field or one simplistic event label.

---

# 13. Milestone 6

## Name

```
Milestone 6 - Evidence History & Interpretation
```

## Status

```
COMPLETE / PRE-COMMIT CHECKPOINT
```

## Primary Goal

Build a persistent evidence/history layer that allows Sentinel to reconstruct and explain the chronological lifecycle of a protected file while preserving the existing Milestone 5 monitoring and reconciliation architecture.

M6 should answer:

```
"What actually happened to this protected file,
 in what order, and what can Sentinel confidently
 conclude from the evidence?"
```

M6 is NOT a replacement for the M5 reconciliation engine.

---

# 14. M6 Core Architecture

Target architecture:

```
Filesystem
    |
    v
Raw filesystem events
    |
    v
Event persistence / history
    |
    v
Reconciliation
    |
    v
Security findings
    |
    v
Finding history
    |
    v
Interpretation
    |
    v
Human-readable timeline / investigation output
```

Important:

Raw events and findings must remain separate concepts.

The history layer should preserve enough evidence to reconstruct a chronological lifecycle without inventing unsupported operations.

---

# 15. M6 Domain Model Requirements

Before implementation, the design must explicitly define the semantics of:

## Event

What the filesystem reported.

An event should retain chronological information and the relevant filesystem paths/evidence available at capture time.

## Finding

What reconciliation concluded relative to the trusted baseline.

Findings should remain linked to the protected target and relevant file identity when possible.

## File Identity

The logical file entity being tracked across path changes.

## Path Transition

A transition such as:

```
old_path -> new_path
```

Path transitions must be distinguishable from baseline-relative previous_path.

## Timeline

A chronological sequence of persisted evidence associated with a logical file.

## Interpretation

A human-readable explanation derived only from supported evidence.

## Confidence

A representation of certainty already supported by the architecture.

If evidence is ambiguous, interpretation must remain ambiguous.

---

# 16. M6 Evidence Rules

Rule 1:

Never discard raw filesystem evidence simply because a finding was generated.

Rule 2:

Never treat a baseline comparison as proof of the latest filesystem operation.

Rule 3:

Never claim an operation occurred if the evidence only proves a final state.

Rule 4:

Never claim a file was "restored" merely because current content equals baseline.

Rule 5:

A restoration conclusion requires evidence that supports:

```
prior state differed
    +
later state matches trusted baseline
```

and the historical sequence must support that interpretation.

Rule 6:

If:

```
current SHA-256 == baseline SHA-256
```

but:

```
metadata != baseline metadata
```

Sentinel should be able to distinguish:

```
CONTENT MATCHES TRUSTED BASELINE
```

from:

```
METADATA DIFFERS FROM TRUSTED BASELINE
```

Rule 7:

Path history must preserve actual observed transitions where evidence exists.

Rule 8:

The baseline path is not automatically the same thing as the immediately previous path.

Rule 9:

History must survive Sentinel process restart.

Rule 10:

History must not mutate the trusted baseline.

Rule 11:

Interpretation must never be more certain than its evidence.

---

# 17. M6 Example: Rename -> Move -> Modify

A valid historical sequence may look conceptually like:

```
Baseline:
    important.txt

Event:
    rename

Path:
    important.txt
        ->
    important-renamed.txt

Event:
    move

Path:
    important-renamed.txt
        ->
    archive\important-renamed.txt

Event:
    modify

Content:
    hash differs from baseline
```

Current state may therefore be:

```
path differs from baseline
content differs from baseline
```

The history layer should preserve both:

```
WHAT HAPPENED
```

and:

```
WHAT THE CURRENT STATE IS
```

---

# 18. M6 Example: Modification Then Restoration

Sequence:

```
Baseline content
    |
    v
content changed
    |
    v
content changed back to baseline
```

The system should not merely report:

```
"MODIFIED"
```

without historical context.

If evidence supports the complete sequence, interpretation may eventually explain:

```
"File content changed and later returned to the trusted baseline."
```

If evidence does not support the sequence, use a weaker statement such as:

```
"Current content matches the trusted baseline."
```

Never infer a restoration solely from matching hashes.

---

# 19. M6 Example: Metadata Difference

If:

```
current SHA-256 == baseline SHA-256
```

but:

```
metadata != baseline metadata
```

Sentinel should be able to represent:

```
Content:
    matches trusted baseline

Metadata:
    differs from trusted baseline
```

The interpretation must not imply that file content is currently compromised.

---

# 20. M6 Example: Delete -> Recreate

M6 must preserve enough history to distinguish scenarios already supported by reconciliation:

```
DELETED_AND_RECREATED_DIFFERENT

DELETED_AND_RECREATED_IDENTICAL

AMBIGUOUS_IDENTICAL_CONTENT
```

Do not collapse these into a generic "modified" event.

If identity cannot be established confidently, preserve ambiguity.

---

# 21. M6 Persistence Requirements

History must be persistent.

Stopping Sentinel must not erase historical evidence.

Restarting Sentinel must not cause previous file history to disappear.

The history layer must not silently rewrite old events.

The trusted baseline must remain immutable unless an explicit future rebaseline workflow is executed.

Database operations should remain transactional where appropriate.

The exact schema must be inspected before designing migrations or new tables.

Do not invent a schema without examining the current database implementation and existing tests.

---

# 22. M6 User-Facing Interpretation Requirements

M6 should eventually make information understandable to a user.

Instead of only:

```
Finding 8:
MOVED_RENAMED_AND_MODIFIED
```

the system should be capable of representing a chronology such as:

```
important.txt

14:02
Renamed:
    important.txt
    ->
    important-renamed.txt

14:04
Content changed.

14:06
Current content matches trusted baseline.

14:08
Moved:
    ->
    archive\important-renamed.txt
```

Current state:

```
Path differs from trusted baseline.
Content matches trusted baseline.
```

The exact final wording is an implementation/UI concern.

The underlying evidence model must come first.

---

# 23. M6 Scope

M6 SHOULD include:

* persistent chronological event history
* persistent finding history/linkage
* file identity linkage
* actual path transition tracking
* separation of raw events and findings
* content-state tracking
* metadata-state tracking
* evidence-aware interpretation
* confidence-aware interpretation
* history surviving process restart
* rename chains
* move chains
* modification chains
* restore scenarios
* delete/recreate scenarios
* ambiguous scenarios
* automated tests
* integration tests
* real filesystem acceptance testing
* preservation of all M1-M5 behavior

---

# 24. M6 Explicitly OUT OF SCOPE

Do NOT implement these as part of M6 unless explicitly approved later:

* GUI
* web dashboard
* iOS application
* Android application
* mobile application
* Windows service
* Windows startup/autostart
* system tray application
* desktop notifications
* email alerts
* cloud backend
* remote synchronization
* AI threat scoring
* machine-learning detection
* ransomware detection
* automatic rebaseline
* automatic baseline replacement
* production deployment packaging
* advanced performance optimization

M6 is about:

```
EVIDENCE
HISTORY
INTERPRETATION
```

Nothing broader.

---

# 25. M6 Acceptance Criteria

M6 cannot be considered complete unless all relevant criteria below pass.

## History

* Chronological filesystem evidence can be persisted.
* Historical evidence survives process restart.
* Historical evidence is associated with the correct protected target.
* File identity is preserved where the platform/evidence supports it.
* Actual path transitions can be reconstructed where observed.

## Findings

* Findings remain distinct from raw events.
* Existing finding semantics remain valid.
* Findings can be associated with historical evidence.
* Baseline-relative state remains distinguishable from latest operation.

## Interpretation

* Content and metadata differences are distinguishable.
* Restoration is not claimed without supporting evidence.
* Ambiguous identity is not presented as certain.
* Interpretation never exceeds evidence.
* Current state can be explained separately from historical operations.

## Compound scenarios

Tests must cover combinations including:

```
modify

rename

move

rename -> modify

rename -> move

rename -> move -> modify

modify -> restore

rename -> restore content

delete -> recreate identical

delete -> recreate different

ambiguous identity/content

repeated modifications

repeated path changes
```

## Regression

All existing M1-M5 automated tests must continue passing.

---

# 26. Verification Strategy

Verification must occur at multiple levels.

## Level 1 - Unit tests

Test individual history and interpretation rules.

## Level 2 - Integration tests

Test:

```
event -> history -> reconciliation -> finding
```

relationships.

## Level 3 - Real filesystem tests

Use actual Windows filesystem operations where practical.

## Level 4 - Database verification

Verify that persisted evidence and history survive process restart.

## Level 5 - Acceptance scenarios

Run deterministic end-to-end scenarios.

## Level 6 - Manual acceptance

Manually perform realistic filesystem changes and inspect chronological output.

A passing unit test alone is not sufficient.

---

# 27. Required M6 Manual Test Scenarios

At minimum, manually test:

1. Modify a protected file.
2. Restore its original content.
3. Rename it.
4. Modify the renamed file.
5. Move the renamed file.
6. Modify the moved file.
7. Stop Sentinel.
8. Restart Sentinel.
9. Verify previous history remains.
10. Continue changing the same file.
11. Delete and recreate a file.
12. Inspect the complete chronological history.

The test should verify both:

```
WHAT SENTINEL DETECTED
```

and:

```
WHY SENTINEL REPORTED IT
```

---

# 28. Known Design Boundary

Do not attempt to solve every history interpretation problem inside the reconciliation engine.

The intended architecture is:

```
Reconciliation
    =
determine current baseline-relative state

History
    =
preserve chronological evidence

Interpretation
    =
explain the evidence and current state
```

If a proposed change mixes these responsibilities, stop and evaluate the architectural impact before implementing it.

---

# 29. Autonomous Development Loop

The development loop must use this document as the persistent source of truth.

Before every implementation iteration:

1. Read this entire document.
2. Determine the current milestone and status.
3. Inspect the existing implementation.
4. Inspect relevant existing tests.
5. Inspect the current database schema before database changes.
6. Identify the highest-priority incomplete requirement.
7. Make a small implementation plan.
8. Implement only within the current milestone scope.

After implementation:

1. Run targeted tests.
2. Inspect test failures.
3. Fix genuine failures.
4. Run the complete test suite.
5. Run milestone acceptance scenarios.
6. Perform real-filesystem verification where required.
7. Review whether behavior matches the architecture.
8. Document genuine newly discovered limitations.
9. Repeat only when necessary.

Do not continue speculative implementation after all acceptance criteria pass.

Maximum autonomous implementation iterations per milestone:

```
6
```

If all acceptance criteria pass before six iterations:

```
STOP.
```

If six iterations are reached:

```
STOP.
```

Report what remains.

---

# 30. Handling Ambiguity

If requirements are ambiguous:

```
STOP
|
v
```

Explain the ambiguity
|
v
Identify affected architecture
|
v
Propose reasonable alternatives
|
v
Wait for human decision when necessary

Do not silently choose an architectural interpretation that could permanently affect Sentinel's security model.

If implementation behavior contradicts this document:

```
STOP
|
v
```

Determine whether:
- implementation is wrong
- documentation is outdated
- requirement has intentionally changed

Do not silently change both.

---

# 31. Security Evidence Rules

Sentinel must favor:

```
accurate uncertainty
```

over:

```
confident speculation
```

Examples:

GOOD:

```
"Current content matches the trusted baseline,
 but metadata differs."
```

GOOD:

```
"The file is currently located at a different path
 from the trusted baseline."
```

GOOD:

```
"Identity could not be established with sufficient
 confidence."
```

BAD:

```
"Attacker modified the file."
```

unless attacker behavior has actually been established by evidence.

BAD:

```
"File was restored."
```

when all Sentinel knows is that the current hash matches baseline.

BAD:

```
"Latest operation was rename."
```

when the evidence only establishes that the current path differs from baseline.

---

# 32. Database Safety

Before modifying database behavior:

1. Inspect current schema.
2. Inspect existing database access functions.
3. Inspect foreign-key relationships.
4. Inspect transaction behavior.
5. Inspect relevant tests.
6. Design migrations/backward compatibility if required.
7. Add tests.
8. Verify existing data behavior.

Do not assume column names.

Do not assume tables contain fields that have not been inspected.

Do not use destructive schema changes without explicit justification.

Do not silently delete historical security evidence.

---

# 33. Testing Safety

NEVER:

* delete tests to make them pass
* weaken assertions
* fake filesystem events when real filesystem testing is practical
* fabricate successful output
* ignore intermittent failures without investigation
* claim a test passed if it was not run
* replace an integration test with a weaker unit test merely for convenience

When a test exposes a genuine implementation flaw:

```
record the flaw
    |
    v
fix the implementation
    |
    v
rerun the test
    |
    v
rerun regression suite
```

---

# 34. Existing Development Rules

ALWAYS:

* inspect architecture before modifying code
* inspect relevant tests
* reuse working functionality
* preserve existing behavior unless a genuine defect requires change
* write tests for new behavior
* use real filesystem operations where practical
* preserve trusted baseline
* keep database operations transactional where appropriate
* verify security-related claims with evidence
* document genuine limitations
* stop when the milestone is actually complete

NEVER:

* add unrelated features
* prematurely implement future milestones
* silently replace the baseline
* treat every filesystem event as a finding
* assume Unix behavior equals Windows behavior
* fabricate evidence
* overstate confidence
* automatically commit
* automatically push
* delete or weaken tests
* rewrite working M1-M5 functionality unnecessarily

---

# 35. Git Rules

The development agent must NOT automatically:

```
git commit
git push
```

After a milestone reaches completion:

1. Stop.
2. Report implementation changes.
3. Report automated test results.
4. Report acceptance results.
5. Report known limitations.
6. Wait for explicit human approval.

Only after explicit human approval may the project be committed.

Only after explicit human approval may the project be pushed.

Before commit, verify:

```
git status
git diff --check
git diff --cached --check
```

Do not include temporary manual-test artifacts in commits unless explicitly intended.

---

# 36. Completed Milestones

## Milestone 1 - File Processing Foundation

Status:

```
COMPLETE
```

Implemented:

* SQLite database
* file ingestion
* metadata persistence
* SHA-256 hashing
* file content persistence
* text processing
* processing result persistence
* transaction handling
* foreign-key enforcement
* rollback behavior
* automated tests

---

## Milestone 2 - Real-Time Filesystem Monitoring

Status:

```
COMPLETE
```

Implemented:

* Windows filesystem monitoring
* watchdog integration
* recursive directory monitoring
* CREATED
* MODIFIED
* MOVED
* DELETED
* event normalization
* event persistence
* real-time CLI output
* clean watcher shutdown

---

## Milestone 3 - Trusted Baseline & Reconciliation

Status:

```
COMPLETE
```

Implemented:

* trusted filesystem baselines
* current-state scanning
* baseline/current reconciliation
* file identity tracking
* SHA-256 comparison
* creation detection
* modification detection
* rename detection
* movement detection
* deletion detection
* compound change detection
* confidence levels
* evidence
* real filesystem scenario testing

Validated reconciliation coverage:

```
17 scenarios
```

Including:

```
MOVED_RENAMED_AND_MODIFIED
METADATA_CHANGED
DELETED_AND_RECREATED_DIFFERENT
DELETED_AND_RECREATED_IDENTICAL
AMBIGUOUS_IDENTICAL_CONTENT
```

---

## Milestone 4 - Protection Management

Status:

```
COMPLETE
```

Implemented:

* protected target model
* FILE target
* DIRECTORY target
* ACTIVE/DISABLED status
* explicit user confirmation
* trusted baseline association
* baseline persistence
* protection listing
* duplicate prevention
* path normalization
* missing-target rejection
* empty-directory handling
* nested-file handling
* symlink/junction rejection
* transaction rollback
* protection acceptance demo

---

## Milestone 5 - Automatic Protected-Target Monitoring

Status:

```
COMPLETE
```

Implemented:

* ACTIVE target discovery
* automatic watcher creation
* target-independent monitoring
* event debounce
* reconciliation
* finding persistence
* continued monitoring
* clean shutdown
* CLI monitor command
* acceptance demo
* real filesystem monitoring tests

Verification:

```
14 automated tests passed
```

Manual filesystem testing completed successfully enough to validate the M5 monitoring workflow.

Known interpretation/history issues are documented above and are intentionally carried into M6.

---

## Milestone 6 - Evidence History & Interpretation

Status:

```
COMPLETE / PRE-COMMIT CHECKPOINT
```

Implemented:

* durable target-scoped watcher observations
* callback-time identity, hash, size, and modification-time evidence
* many-to-many finding-to-observation links
* deterministic evidence ordering by persistent observation ID
* transaction-safe persistence and visible persistence failures
* FILE-target identity continuity through rename, move, and restart rediscovery
* conservative evidence-backed finding interpretation
* protection enable/disable preservation of baseline, findings, and evidence
* M6 integration and history tests

Verification:

```
26 automated tests passed
```

`m6_test/` is manual runtime evidence only and is intentionally excluded from the milestone commit.

---

# 37. Current Milestone

Current milestone:

```
Milestone 6 - Evidence History & Interpretation
```

Current status:

```
COMPLETE / PRE-COMMIT CHECKPOINT
```

Immediate task:

```
Review the M6 diff, run the complete test suite, and obtain approval
before committing the milestone checkpoint.
```

M7 work must not be mixed into the M6 checkpoint.

---

# 38. Council Review Requirement

Before major milestone implementation, Sentinel development should use a design review / Council process.

The Council should challenge:

* architectural assumptions
* data model choices
* evidence semantics
* security implications
* ambiguity handling
* scope creep
* testing adequacy
* regression risk

Council recommendations are advisory until accepted by the human project owner.

Do not treat speculative Council suggestions as requirements automatically.

The final accepted milestone requirements must be reflected in this document.

---

# 39. Roadmap

Current roadmap:

```
M1  File Processing Foundation
    COMPLETE

M2  Real-Time Filesystem Monitoring
    COMPLETE

M3  Trusted Baseline & Reconciliation
    COMPLETE

M4  Protection Management
    COMPLETE

M5  Automatic Protected-Target Monitoring
    COMPLETE

M6  Evidence History & Interpretation
    CURRENT

M7  Real-Time Alerts / Notifications
    FUTURE

M8  Reporting & Investigation Interface
    FUTURE

M9  Windows Background Service / Autonomous Operation
    FUTURE

M10+ Security Hardening, Reliability, Recovery,
     Performance, Production Readiness,
     Advanced Detection
    FUTURE
```

Roadmap items may change after architectural review.

Do not implement future milestones prematurely.

---

# 40. Current Project State Summary

Sentinel currently has:

```
File processing                    COMPLETE
Filesystem monitoring              COMPLETE
Trusted baselines                  COMPLETE
Protection management              COMPLETE
Automatic ACTIVE-target monitoring COMPLETE
```

Sentinel currently does NOT yet have:

```
Persistent chronological history    NOT COMPLETE
Full historical interpretation      NOT COMPLETE
Real-time user alert system         NOT COMPLETE
Investigation interface             NOT COMPLETE
Windows background service          NOT COMPLETE
Mobile application                  NOT COMPLETE
Cloud backend                       NOT COMPLETE
Automatic rebaseline                NOT COMPLETE
```

Current priority:

```
Milestone 6
Evidence History & Interpretation
```

The immediate objective is not to add more features.

The immediate objective is to make Sentinel's existing security evidence:

```
persistent
chronological
explainable
defensible
accurate
confidence-aware
```

---

# 41. Final Operating Principle

When uncertain, prefer:

```
PRESERVE EVIDENCE
```

over:

```
SIMPLIFYING THE STORY
```

Prefer:

```
ACCURATE UNCERTAINTY
```

over:

```
FALSE CERTAINTY
```

Prefer:

```
SMALL VERIFIED CHANGES
```

over:

```
LARGE UNTESTED REWRITES
```

Prefer:

```
CLEAR ARCHITECTURE
```

over:

```
PREMATURE FEATURES
```

Sentinel is a security-oriented system.

Its credibility depends not only on detecting change, but on being able to explain:

```
WHAT HAPPENED
WHEN IT HAPPENED
WHAT EVIDENCE SUPPORTS IT
WHAT THE CURRENT STATE IS
WHAT SENTINEL DOES NOT KNOW
```

The development process must preserve those principles throughout every future milestone.
# 42. Council Amendments - M6 Mandatory Design Rules

The following requirements were established during the M6 Council review.

These requirements are mandatory for Milestone 6 implementation.

---

## 42.1 Explicit Separation of Events, Findings, and Interpretations

Sentinel must maintain three distinct concepts.

### Raw Filesystem Event

A raw filesystem event is an observation reported by the filesystem watcher.

Examples:

```
CREATED
MODIFIED
MOVED
DELETED
```

A raw event describes what the filesystem reported.

It does not automatically establish what happened relative to the trusted baseline.

---

### Security Finding

A security finding is the result of Sentinel's reconciliation process.

A finding describes what Sentinel determined after comparing observed/current state against the trusted baseline.

Examples:

```
MODIFIED
RENAMED
MOVED
METADATA_CHANGED
DELETED_AND_RECREATED_IDENTICAL
```

A finding must not be treated as an exact record of the latest filesystem operation unless the evidence supports that conclusion.

---

### Interpretation

An interpretation is a human-readable explanation derived from available evidence.

An interpretation must be based on:

```
raw events
+
reconciliation findings
+
baseline state
+
current state
+
file identity evidence
+
chronology
+
confidence
```

Do not implement interpretation as a simple mapping such as:

```
finding_type -> fixed sentence
```

unless that sentence is guaranteed to be correct for every possible evidence state represented by that finding.

The interpretation layer must not claim more than the evidence establishes.

---

## 42.2 Evidence-Linked Interpretation

Every meaningful historical interpretation must be traceable to supporting evidence.

Conceptually:

```
INTERPRETATION
    |
    +-- supporting event(s)
    |
    +-- supporting finding(s)
    |
    +-- baseline comparison
    |
    +-- current state
    |
    +-- file identity evidence
    |
    +-- chronology
    |
    +-- confidence
```

The exact implementation may differ, but the architectural relationship must remain.

Examples:

### Supported

If history contains:

```
content differed from baseline
    |
    v
later content matches baseline
```

then Sentinel may interpret:

```
"File content changed and later returned to the trusted baseline."
```

provided the historical evidence is sufficient.

### Not Supported

If Sentinel only knows:

```
current hash == baseline hash
```

it must NOT automatically interpret:

```
"File was restored."
```

The file may have changed while Sentinel was offline, or Sentinel may not have observed the earlier modification.

The correct weaker interpretation may be:

```
"Current content matches the trusted baseline."
```

---

## 42.3 Persistence Failure Handling

M6 must explicitly account for persistence failures.

The system must not silently report historical completeness when an event or finding could not be persisted.

At minimum, tests must cover scenarios where:

```
filesystem event occurs
    |
    v
history persistence fails
    |
    v
system remains internally consistent
```

The implementation must determine the appropriate transactional/error-handling behavior based on the existing database architecture.

Do not invent silent recovery behavior.

Do not silently discard persistence errors.

Do not claim evidence exists in the historical record when the database write failed.

If a persistence failure causes loss of evidence, that limitation/error must be observable and testable.

Existing transaction and rollback behavior from previous milestones must be preserved.

---

## 42.4 Event Debouncing vs Historical Evidence Preservation

M6 must explicitly distinguish watcher-level event debouncing from historical evidence preservation.

Filesystem watchers may emit multiple low-level events for one logical user operation.

Sentinel may need to debounce or normalize these events before reconciliation.

However, historical evidence must not be destroyed merely because multiple events appear similar.

The architecture must avoid both extremes:

```
BAD:
Store every noisy watcher callback as an independent
user-visible historical operation.
```

and:

```
BAD:
Aggressively deduplicate events until genuine historical
information is lost.
```

The implementation must define a clear boundary between:

```
RAW OBSERVATION
    |
    v
EVENT NORMALIZATION / DEBOUNCING
    |
    v
PERSISTED EVIDENCE
    |
    v
RECONCILIATION
    |
    v
FINDING
    |
    v
INTERPRETATION
```

The existing M5 debounce/normalization behavior must be inspected and preserved unless M6 identifies a concrete defect.

Any change to M5 event behavior must include regression tests.

---

# 43. Council-Approved M6 Implementation Gate

M6 is approved for implementation only after these requirements are incorporated into the design.

Before writing implementation code, Codex must:

1. Read this entire development-state file.
2. Inspect the existing repository architecture.
3. Inspect the existing database schema.
4. Inspect existing monitoring code.
5. Inspect existing reconciliation code.
6. Inspect existing protection code.
7. Inspect existing M1-M5 tests.
8. Determine how raw events are currently represented.
9. Determine how findings are currently represented.
10. Determine what existing identity information can be reused.
11. Propose the smallest coherent M6 architecture.
12. Identify any migration requirements before modifying the database.
13. Add tests before or alongside new implementation where practical.

Codex must NOT immediately begin a large rewrite.

The first implementation iteration must be based on the actual repository state, not assumptions from this document alone.

---

# 44. Council Decision

Council status:

```
M6 APPROVED FOR IMPLEMENTATION
```

Conditions:

```
- Event/finding/interpretation separation is mandatory.
- Interpretations must be evidence-linked.
- Persistence failures must be handled explicitly.
- Debouncing must remain distinct from evidence preservation.
- M1-M5 behavior must remain regression-safe.
- Trusted baseline remains immutable.
- M6 scope remains limited to evidence, history, and interpretation.
```

No future milestone functionality should be implemented merely because it could be useful to M6.

The next step after this document is verified is the M6 looping implementation prompt.
# 45. M6 Council Findings From Repository Review

The M6 Council reviewed the actual Sentinel architecture and existing M1-M5 implementation.

These findings are repository-specific and must be treated as implementation constraints for M6.

---

## 45.1 Critical M5 Finding: Watcher Evidence Is Currently Discarded

The current monitoring path receives filesystem event information but `MonitoringCoordinator._on_event()` currently uses the event to trigger debounce/reconciliation without preserving the complete event payload as durable historical evidence.

As a result:

```
FILESYSTEM EVENT
    |
    v
DEBOUNCE
    |
    v
RECONCILIATION
    |
    v
FINDING
```

does not currently preserve enough information to reconstruct the chronological operation history.

M6 must change this flow to preserve an observation before or independently of the later reconciliation result:

```
FILESYSTEM EVENT
    |
    v
CAPTURE OBSERVATION
    |
    v
PERSIST EVIDENCE
    |
    v
DEBOUNCE / RECONCILE
    |
    v
FINDING
    |
    v
LINK FINDING TO SUPPORTING EVIDENCE
    |
    v
INTERPRETATION
```

The exact implementation must be determined after inspecting the existing architecture.

Do not rewrite the monitoring system unnecessarily.

---

## 45.2 Existing Finding Paths Are Baseline-Relative

The existing `security_findings.previous_path` field represents the path associated with the previous/trusted state used during reconciliation.

It must NOT be reinterpreted as:

```
"the immediately previous filesystem path"
```

and must NOT be used as a substitute for chronological history.

For example:

```
baseline:
    important.txt

current:
    archive\important.txt
```

A finding containing:

```
previous_path = important.txt
current_path = archive\important.txt
```

means that the current path differs from the baseline path.

It does not by itself prove that the most recent filesystem operation was a rename or move.

M6 must preserve actual observed path transitions separately from baseline-relative path comparison.

---

## 45.3 Existing File Identity Logic Must Be Reused

M3 already contains Windows filesystem identity and reconciliation logic.

M6 must reuse that logic where appropriate.

File identity is evidence supporting continuity of a logical file.

It is not absolute proof of user intent.

Identity may be insufficient or unavailable in cases such as:

```
delete
recreate
ambiguous identical content
delayed reconciliation
missing identity information
```

M6 must not create an unrelated competing file-identity system merely to support history.

### M6 Manual Acceptance Regression: FILE Target Continuity

Manual acceptance testing exposed a FILE-target admission defect: after a
protected file was renamed, a later move was discarded because admission was
still comparing event paths only with the immutable baseline path.

Architectural rule:

```
For a FILE target, the original protected-target path and baseline path remain
immutable baseline evidence.  They are not the only admissible current path.
Events below the watched parent must be attributed only when the existing
filesystem identity supports continuity with the protected baseline file (or
when a previously identity-confirmed path is needed for an event with no
remaining file, such as deletion).
```

This preserves the narrow FILE-target security boundary: watching the parent
directory is an implementation boundary, not permission to treat unrelated
files in it as protected.  It also preserves `previous_path` as a
baseline-relative field; chronological path transitions belong in durable
evidence observations.

### M6 Startup and Restart Continuity for FILE Targets

An ACTIVE protected FILE remains monitorable after its immutable baseline path
disappears.  At startup, Sentinel first treats persisted evidence paths as
rediscovery hints, then validates each candidate against the trusted baseline
file identity.  If needed, it searches recursively only within the original
protected file's parent directory: the existing FILE watcher boundary.

The resulting current runtime path is held only in coordinator runtime state.
It never changes the immutable protection path, baseline path/hash/identity,
or baseline-relative `previous_path`.  Filename, size, hash, proximity, and
history alone are insufficient to adopt a candidate; current filesystem
identity must match.  This bounded identity check preserves unrelated-file
isolation while allowing rename/move continuity across shutdown and restart.

### M6 Windows Cross-Directory Move Evidence

On the verified Windows/watchdog sequence, a cross-directory relocation inside
the FILE watcher boundary can arrive as raw `DELETED` at the old path followed
by raw `CREATED` at the destination, rather than as one `MOVED` callback.
Sentinel persists those raw observations unchanged.  When the destination's
current filesystem identity matches the protected baseline and exactly one
previously tracked runtime path is absent, Sentinel also persists an
`INFERRED_MOVED` observation with `old_path` and `new_path`.

`INFERRED_MOVED` is explicitly derived evidence, not a watcher callback.  It
exists so path-transition history remains queryable while preserving the raw
event sequence and uncertainty boundary.  Ambiguous, identity-mismatched, or
unrelated create events must not produce it.

---

## 45.4 Current In-Memory Signature State Is Not Historical Truth

The existing monitoring implementation contains in-memory signature/deduplication state.

This state:

```
does not survive process restart
cannot serve as the persistent historical record
must not be treated as proof of previous filesystem state after restart
```

M6 history must be persisted in SQLite.

After:

```
Sentinel running
    |
    v
filesystem changes
    |
    v
Sentinel shutdown
    |
    v
Sentinel restart
    |
    v
additional filesystem changes
```

the historical record must retain the earlier history and continue from it.

---

## 45.5 Existing Database Requires Additive M6 Evidence Modeling

The existing database contains structures established by earlier milestones, including:

```
filesystem_events
security_findings
protected_targets
baseline-related records
```

M6 must inspect and preserve these structures.

The existing `filesystem_events` structure was designed during M2 and does not contain all associations required for M6 historical reconstruction.

The existing `security_findings` structure is finding-oriented and does not by itself provide a complete evidence graph.

Therefore M6 may require an additive database migration.

M6 must NOT:

```
replace the trusted baseline
delete existing historical rows
repurpose baseline-relative fields
destroy M1-M5 data
silently alter the semantics of existing fields
```

If schema changes are required, preserve existing data and verify migration/rollback behavior.

---

## 45.6 Evidence and Finding Relationship

M6 must support the possibility that:

```
one observation
    |
    +----> finding A
    |
    +----> finding B
```

and:

```
finding A
    |
    +----> observation 1
    +----> observation 2
    +----> observation 3
```

Therefore the implementation must not assume a permanent one-to-one relationship between an event and a finding.

The exact database relationship must be determined from the existing schema and the minimum requirements of the milestone.

The goal is an evidence relationship capable of answering:

```
"Why did Sentinel generate this finding?"
```

---

## 45.7 Deterministic Historical Ordering

Filesystem timestamps alone must not be treated as a guaranteed total ordering.

Multiple events may have equal or insufficiently precise timestamps.

M6 history must therefore have a deterministic persisted ordering mechanism.

The implementation should use a database-generated or otherwise persistent sequence/order mechanism where appropriate.

The chronological timeline must remain deterministic after:

```
process restart
database reload
multiple events with identical timestamps
```

Do not rely exclusively on wall-clock timestamps for ordering.

---

## 45.8 Metadata Interpretation Must Be Explicit

The currently supported metadata/content comparison must be understood precisely.

Where the existing architecture compares attributes such as:

```
modified_time_ns
size
SHA-256 hash
```

M6 interpretation must distinguish:

```
CONTENT DIFFERENCE
```

from:

```
METADATA DIFFERENCE
```

For example:

```
hash unchanged
metadata changed
```

must not be described as:

```
"file content was modified"
```

unless content evidence actually establishes that.

Likewise, metadata differences must identify the supported comparison category where practical.

Do not claim that metadata changed if the implementation cannot identify which supported metadata attribute differed.

---

## 45.9 Restoration Interpretation Rule

M6 must not infer restoration solely from:

```
current hash == trusted baseline hash
```

A valid restoration interpretation requires historical evidence that:

```
previous persisted state differed
    |
    v
later persisted state matches trusted baseline
```

If that evidence does not exist, Sentinel may state:

```
"Current content matches the trusted baseline."
```

It must not automatically state:

```
"File was restored."
```

This distinction is mandatory because Sentinel may have been offline or may not have observed the earlier modification.

---

## 45.10 Event Observation vs Meaningful Timeline

M6 must distinguish between:

```
watcher-level observations
```

and:

```
meaningful historical operations/findings
```

Filesystem watcher implementations may emit multiple callbacks for a single logical filesystem operation.

Therefore:

```
RAW OBSERVATION
    |
    v
NORMALIZATION / DEBOUNCING
    |
    v
RECONCILIATION
    |
    v
MEANINGFUL FINDING
```

must remain conceptually distinct.

Do not blindly expose every watcher callback as a separate user-facing operation.

At the same time, do not aggressively deduplicate observations in a way that destroys evidence needed to explain a finding.

The implementation must preserve sufficient evidence while producing a meaningful chronological history.

---

## 45.11 Persistence Ordering Rule

A historical observation must not be considered durably recorded until its database transaction succeeds.

Likewise, derived in-memory state and downstream notification/sink behavior must not claim successful persistence before the relevant transaction commits.

If persistence fails:

```
do not silently discard the error
do not claim the evidence was recorded
do not advance historical state as though persistence succeeded
do not produce an inconsistent finding/evidence relationship
```

The exact recovery behavior must follow the existing transactional architecture.

---

## 45.12 M6 Required Sequence Scenarios

M6 testing must validate complete sequences rather than only isolated final states.

Required scenarios include:

### Modify then restore

```
trusted
    |
    v
content modified
    |
    v
content returns to trusted state
```

Expected:

```
history preserves the sequence
interpretation distinguishes observed change from current state
"restored" is only used when historical evidence supports it
```

---

### Rename then modify

```
trusted A.txt
    |
    v
rename -> B.txt
    |
    v
modify B.txt
```

The final interpretation must not incorrectly describe the latest operation merely as a rename.

---

### Modify then rename

```
trusted A.txt
    |
    v
modify A.txt
    |
    v
rename -> B.txt
```

The history must preserve the order and the final state.

---

### Rename then move then modify

```
A.txt
    |
    v
B.txt
    |
    v
archive\B.txt
    |
    v
modified content
```

The logical file lifecycle must remain understandable.

---

### Delete and recreate identical

The history must distinguish:

```
previous file deleted
new file appeared with identical content
```

from proof that the exact original file was restored.

---

### Delete and recreate different

The history must preserve the deletion and replacement relationship without falsely assigning original identity.

---

### Ambiguous identity

The history must preserve uncertainty instead of inventing a definitive lifecycle.

---

### Restart continuity

```
Sentinel running
    |
    v
change 1
    |
    v
shutdown
    |
    v
restart
    |
    v
change 2
```

The persisted history must contain both events in deterministic chronological/order sequence.

---

## 45.13 M6 Regression Requirement

M6 must preserve all relevant M1-M5 behavior.

At minimum, regression verification must cover:

```
database foreign-key enforcement
transaction rollback
baseline immutability
protection behavior
active/disabled target behavior
target independence
watcher normalization
debounce behavior
Windows file identity lifecycle
reconciliation findings
existing real-filesystem scenarios
```

A green M6-specific test suite is not sufficient if existing M1-M5 behavior regresses.

---

## 45.14 M6 Implementation Boundary

M6 is limited to:

```
persistent evidence
chronological file history
event/finding relationships
evidence-supported interpretation
metadata/content distinction
deterministic historical ordering
CLI/programmatic verification of history
```

M6 must NOT expand into:

```
GUI
desktop notifications
email alerts
mobile application
cloud reporting
AI threat attribution
ransomware detection
automatic rebaseline
Windows service
startup/autostart
production deployment
retention-policy system
```

Those remain future milestones.

---

## 45.15 Council Implementation Decision

Repository review result:

```
M6 = APPROVED WITH REQUIRED CHANGES
```

Primary architectural change:

```
Sentinel must preserve watcher observations as durable evidence
before relying on later reconciliation to explain what happened.
```

Primary semantic rule:

```
Current baseline-relative state
!=
chronological operation history
```

Primary security rule:

```
Evidence-supported uncertainty
>
unsupported certainty
```

Primary database rule:

```
Prefer the smallest additive schema change that preserves
existing M1-M5 data and semantics.
```

Primary engineering rule:

```
Reuse working M1-M5 architecture wherever possible.
```

M6 implementation is complete. The next action is human approval of the
pre-commit checkpoint; no automatic commit or push is permitted.
