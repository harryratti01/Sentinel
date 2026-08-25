# Sentinel Development State

## 1. Project Vision

Sentinel is being developed as a Windows file-integrity and security
monitoring tool.

The long-term vision is:

User selects files or folders
→ explicitly confirms their current state as trusted
→ Sentinel creates a trusted baseline
→ Sentinel continuously monitors protected targets
→ filesystem changes are detected
→ changes are compared against the trusted baseline
→ Sentinel determines what actually happened
→ meaningful security findings are generated
→ the user receives real-time alerts and reports
→ Sentinel eventually operates autonomously in the Windows background.

The system should focus on understanding changes relative to a trusted
state, not merely reporting raw filesystem events.

---

## 2. Development Philosophy

Build Sentinel incrementally.

Use:

    BUILD → TEST → VERIFY → STRENGTHEN → BUILD AGAIN

Do not attempt to make Sentinel production-ready prematurely.

Production hardening, Windows service behavior, startup behavior,
security hardening, performance optimization, and advanced threat
detection will be developed later.

Correctness and clear architecture come first.

---

## 3. Completed Milestones

### Milestone 1 — File Processing Foundation
Status: COMPLETE

Implemented:

- SQLite database
- File ingestion
- File metadata persistence
- SHA-256 hashing
- File content persistence
- Basic text processing
- Processing result persistence
- Transaction handling
- Foreign-key enforcement
- Failure rollback
- Automated tests

---

### Milestone 2 — Real-Time Filesystem Monitoring
Status: COMPLETE

Implemented:

- Windows filesystem monitoring using watchdog
- Recursive directory monitoring
- CREATED events
- MODIFIED events
- MOVED events
- DELETED events
- Event normalization
- Event persistence
- Real-time CLI event output
- Clean watcher shutdown

---

### Milestone 3 — Trusted Baseline and Reconciliation
Status: COMPLETE

Implemented:

- Trusted filesystem baselines
- Current-state scanning
- Baseline/current-state reconciliation
- File identity tracking
- SHA-256 comparison
- CREATED detection
- MODIFIED detection
- RENAMED detection
- MOVED detection
- DELETED detection
- Compound change detection
- MOVED_RENAMED_AND_MODIFIED
- METADATA_CHANGED
- DELETED_AND_RECREATED_DIFFERENT
- DELETED_AND_RECREATED_IDENTICAL
- AMBIGUOUS_IDENTICAL_CONTENT
- Confidence levels
- Evidence for findings
- Real-filesystem scenario testing

Current validated coverage:

- 17 reconciliation scenarios
- Windows filesystem identity lifecycle tests
- Real temporary filesystem operations

---

### Milestone 4 — Protection Management
Status: COMPLETE

Implemented:

- Protected target model
- FILE and DIRECTORY targets
- ACTIVE and DISABLED status model
- Explicit user confirmation
- Trusted baseline associated with protected target
- Baseline file persistence
- Protection listing
- Duplicate protection prevention
- Windows path normalization
- Missing-target rejection
- Empty-directory handling
- Nested file handling
- Symlink/junction rejection
- Transaction rollback
- Protection acceptance demo

Current behavior:

    protect <path>
        ↓
    inspect target
        ↓
    show summary
        ↓
    explicit user confirmation
        ↓
    create trusted baseline
        ↓
    create protected target
        ↓
    associate baseline with target

IMPORTANT:

Protection currently establishes the trusted state but does not
automatically start monitoring.

That is the purpose of Milestone 5.

---

## 4. Current Milestone

### Milestone 5 — Automatic Monitoring of Protected Targets
Status: IN PROGRESS

Primary goal:

Connect:

    Protected Target
        ↓
    Trusted Baseline
        ↓
    Filesystem Watcher
        ↓
    Reconciliation
        ↓
    Security Finding

When a protected target is ACTIVE, Sentinel should automatically
discover it and monitor it.

The user should NOT need to manually start a separate watcher for
each protected target.

The desired workflow is:

    User protects folder
        ↓
    Baseline created
        ↓
    Protection becomes ACTIVE
        ↓
    Sentinel monitoring process discovers ACTIVE target
        ↓
    Watcher monitors target
        ↓
    Filesystem change occurs
        ↓
    Event captured
        ↓
    Current state reconciled against trusted baseline
        ↓
    Finding generated and persisted

Milestone 5 does NOT yet require:

- Windows service
- Windows startup/autostart
- system tray application
- desktop notifications
- email alerts
- GUI
- cloud reporting
- AI threat analysis
- ransomware detection
- automatic rebaseline

Those belong to later milestones.

---

## 5. Development Rules

### ALWAYS

- Inspect the existing architecture before changing code.
- Reuse working functionality.
- Prefer small, coherent changes.
- Write tests for new behavior.
- Use real filesystem operations for filesystem behavior where practical.
- Preserve existing behavior unless a genuine bug requires changing it.
- Run the full test suite after meaningful changes.
- Use acceptance tests for milestone-level verification.
- Investigate test failures rather than hiding them.
- Document genuine limitations.
- Keep database operations transactional where appropriate.
- Preserve the trusted baseline unless an explicit future rebaseline
  operation is requested.

### NEVER

- Do not automatically commit.
- Do not automatically push.
- Do not delete tests to make them pass.
- Do not weaken assertions just to obtain a green test suite.
- Do not change acceptance criteria merely because implementation is
  difficult.
- Do not fabricate test results.
- Do not claim success without verification.
- Do not silently ignore errors.
- Do not add unrelated features.
- Do not unnecessarily rewrite working Milestone 1–4 components.
- Do not silently replace a trusted baseline when a file changes.
- Do not treat every raw filesystem event as a security finding.
- Do not assume Unix filesystem behavior is identical to Windows behavior.

---

## 6. Verification Philosophy

A passing unit test alone is NOT sufficient evidence that a Sentinel
milestone works.

Use multiple verification layers:

1. Unit tests
2. Integration tests
3. Real filesystem scenarios
4. Database verification where appropriate
5. Deterministic acceptance demos
6. Manual acceptance when appropriate

For security-related behavior, verify both:

    WHAT HAPPENED

and:

    WHY SENTINEL CONCLUDED THAT

Findings should be supported by evidence and confidence where the
architecture provides those concepts.

Ambiguous situations must not be presented as certain.

---

## 7. Autonomous Development Loop

For milestone implementation, use this loop:

    DISCOVER
        ↓
    PLAN
        ↓
    IMPLEMENT
        ↓
    TEST
        ↓
    REVIEW
        ↓
    FIX
        ↓
    TEST AGAIN
        ↓
    PASS → STOP
    FAIL → ITERATE

Before each iteration:

1. Read this development-state file.
2. Inspect the current implementation.
3. Inspect relevant existing tests.
4. Identify the highest-priority incomplete requirement.

After implementation:

1. Run targeted tests.
2. Run the complete test suite.
3. Run the milestone acceptance scenario.
4. Inspect failures.
5. Fix genuine problems.
6. Repeat verification.

Maximum autonomous implementation iterations per milestone:

    6

If all acceptance criteria pass before the limit:

    STOP.

If the iteration limit is reached:

    STOP.

Report what remains instead of continuing speculative changes.

---

## 8. Completion Standard

A milestone is COMPLETE only when:

- Required functionality is implemented.
- Required tests exist.
- Relevant real-filesystem behavior has been tested.
- Existing tests still pass.
- Acceptance criteria pass.
- Known limitations are documented.
- No unrelated work has been introduced.

Passing tests alone does not automatically make a milestone complete.

The implementation must also satisfy the intended architecture and
user workflow.

---

## 9. Current Known Limitations

At the beginning of Milestone 5:

- Protected targets do not automatically start monitoring.
- No Windows background service exists.
- No Windows startup/autostart exists.
- No desktop notification system exists.
- No reporting/dashboard exists.
- No automatic rebaseline workflow exists.
- Sentinel is not yet production-hardened.

These are known future work items, not current failures.

---

## 10. Next Milestones

Planned direction:

### Milestone 5
Automatic monitoring of ACTIVE protected targets.

### Milestone 6
Real-time security alerts/findings delivery.

### Milestone 7
Reporting and investigation interface.

### Milestone 8
Windows background operation/service.

### Milestone 9+
Security hardening, reliability, performance, recovery,
production-readiness, and advanced detection.

These milestones may change as the architecture develops.

Do not implement future milestones prematurely.

---

## 11. Git Safety

The development agent must NOT commit or push changes automatically.

After a milestone passes:

1. Stop.
2. Report the changes.
3. Report test results.
4. Report acceptance results.
5. Wait for human review and approval.

Only after explicit approval should the project be committed/pushed.