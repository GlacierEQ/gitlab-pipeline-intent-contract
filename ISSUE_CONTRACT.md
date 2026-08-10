# Issue contract — Pipeline Intent Contract

## Problem
CI pipelines expand permissions without a frozen intent contract for what the pipeline may touch.

## Desired outcome
A bounded, open, testable implementation of **Pipeline Intent Contract** that demonstrates Compile a pipeline intent contract (paths, secrets, environments) and fail closed on drift.

## Non-goals
- GitLab affiliation or proprietary integration
- Portfolio-wide scale/performance claims
- UI marketing site

## Acceptance
1. Mechanism module implements allow + refuse with structured receipts
2. pytest behavioral suite green
3. operate.py cold-start produces JSON receipt
4. Non-affiliation disclaimer preserved
