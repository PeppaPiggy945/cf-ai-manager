# Network prefix learning implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Implement inline; request one fresh final review.

**Goal:** Adapt CF candidate quotas to completed real tunnel evidence for the current network while preserving new-address exploration.

**Architecture:** A small discovery module owns bounded, decaying per-context learning and sampling. Scanner supplies completed probe evidence and guards persistence. Existing GUI displays actual quotas using coverage metadata.

**Tech Stack:** Python stdlib, unittest, existing PySide6 and Mihomo fixtures.

**Spec:** ../specs/2026-10-27-network-prefix-learning-design.md

## Global Constraints

- 70% preference/retest, at least 30% fresh exploration; existing total scan/download budgets unchanged.
- Scope learning to physical identity, template fingerprint, two probe URLs and timeout; no credentials in persisted learning.
- Last 30 days / 32 batch summaries per prefix; 7-day half-life; at most 8 contexts.
- No production scan, restart, startup migration, or active proxy selection change.
- Preserve the uncommitted 0.2.5 fixes this feature depends on; leave changes reviewable together.

## Review Focus

- Many seed IPs must not displace fresh exploration (Task 1 test).
- TCP-fast but tunnel-failed ranges must not win preference (Task 1 test).
- Canceled/interrupted or changed-network batches must not change preference evidence (Task 2 test).
- Corrupt/future/stale learning must fall back without breaking scans (Task 1 test).
- Evidence sparsity and an exhausted small prefix must still yield bounded diverse exploration (Task 1 test).

### Task 1: Learning and allocation

Files: create cfai/discovery.py and tests/test_discovery.py.

Interfaces: PrefixLearning(path, profile, network_identity, now=None); scores(ranges); plan(ranges, excluded, seeds, count) -> (ips, coverage); validation_order(rows, ranges); record(rows, ranges); save(). Sampling mutates per-context cursors, record mutates completed evidence, save persists with context pruning.

- [x] Write behavior tests for isolation, weighting, decay, cold start, quota conservation, seed cap, bounds, corruption recovery and address exhaustion. Run unittest discovery for test_discovery.py and observe missing-feature failure.
- [x] Implement fixed policy constants, context hashing, bounded records, 70/30 per-prefix sampling and evidence prioritization.
- [x] Re-run test_discovery.py; require PASS.

### Task 2: Scanner integration and guarded learning

Files: modify cfai/scanner.py; create tests/test_discovery_scan.py; update existing scan task tests only where behavior intentionally changes.

Consumes Task 1's PrefixLearning interface. Extend shortlist(..., exploration=None) so validation preserves a 30% exploration reserve, leaving the download call unchanged.

- [x] Write failing tests for two batches preferring the successful prefix, overfull seed/history input preserving exploration validation, cancellation and changed-network batch preserving stored evidence.
- [x] Integrate planning after network verification, save cursors after TCP, learn only after final network/cancel guards and saved results. Populate coverage with actual preference, seed and exploration counts, per-prefix allocations, scores and validation quotas.
- [x] Run discovery and scan tests, then full unittest suite; require PASS.

### Task 3: Presentation, review and release

Files: cfai/gui.py, cfai/__init__.py, README.md, tests/test_gui_generation.py.

- [x] Write a failing GUI assertion for actual learned allocation display, then implement concise progress/result text and document policy, identity limits and state file.
- [x] Set version 0.2.6; run full unittest discover, source self-test and git diff --check. Request fresh review of changed source against this spec; fix important findings with regression tests.
- [x] Build with build.py --output-dir dist/preview-0.2.6. Run packaged --self-test using isolated validation output; verify manifest hashes/archive exclusions. Leave active 0.2.4/0.2.5 unchanged and link the package.
