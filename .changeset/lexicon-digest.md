---
'@mcpguard/detect': patch
---

The ruleset digest now covers the lexicons as well as the rules. The imperative
and encoding detectors read the lexicons and they move the score, so two
rulesets with the same rules and different lexicons used to carry the same
digest and could decide differently. Every ruleset's digest changes with this
release. Audit records written by an earlier engine version carry the old
formula; reproduce them with that engine version, which ADR-009 already
requires.
