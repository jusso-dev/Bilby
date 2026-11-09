# 0005: Findings carry severity and confidence

Date: 2026-11-09. Status: Accepted.

## Context

Most "is my PC infected" tools either find nothing or find 200 scary "threats" (tracking cookies, registry leftovers). Both teach people to ignore them. Bilby has to be believable when it does raise the alarm.

## Decision

- Every finding has a severity (Info, Low, Medium, High: how bad it would be if true) and a confidence (Low, Medium, High: how likely it's true).
- The overall light is computed from both, using the rules in `docs/architecture.md` under "Scoring".
- A rule may only claim High confidence if it's documented in `docs/signals.md` with a reason a clean machine wouldn't produce it, and the clean-VM baseline in the test plan doesn't trigger it.
- Rules lower their own confidence when there's evidence the item is normal: signed by a well-known publisher, installed under Program Files, present in the clean baseline, known good by hash (if online checks are on).
- Users can mark a finding "I know this one". It's stored as rule id plus subject and stops counting toward the light.
- Every screen shows the confidence in words: "We're fairly sure", "This might be nothing", and so on.

## Consequences

- Rules need fixture tests for both the bad case and the look-alike good case.
- The clean-VM baseline becomes a release gate: zero Medium-or-higher findings on a fresh Windows 11 install with common apps.
