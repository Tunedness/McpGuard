---
'@tunedness/mcpguard': minor
'@tunedness/mcpguard-core': minor
'@tunedness/mcpguard-detect': minor
'@tunedness/mcpguard-ruleset': minor
---

PII masking gains an opt-in health profile. `pii.profile: health` adds five
recognisers: `health_ref` (a hospital, e-prescription or insurer number after an
anchor word such as `protokol no`, `MRN`), `health_date` (a real calendar date
beside `doğum tarihi`, `DOB`, `taburcu` and the like), `gs1_serial` (a medicine
pack's GTIN and serial together; a GTIN alone is never masked), `ssn_us` and
`mbi_us`. Two more, `icd10` and `atc`, are never switched on by the profile: a
diagnosis or a drug class is what a clinical agent often needs to read, so they
run only when named in `pii.recognizers`. With the profile off, which is the
default, nothing changes: the same six recognisers run and the output is
byte-for-byte what it was.

The keyword lists live in the ruleset (`@tunedness/mcpguard-ruleset/pii/`), as
words and never as patterns, with their own digest. A verdict carries it as
`piiDigest`, and only when the health profile was on or a recogniser that is not a
base kind was named; the
ruleset's `digest` does not cover it. The same lists carry exclusion words
(`kargo`, `courier`, `webhook`...) that keep a courier's tracking number or a
Kubernetes admission date from being masked as clinical, but never override a
plainly clinical anchor (`reçete no`, `hasta no`, `MRN`, `date of birth`, and
the health-claim and plan anchors `claim #`, `member id`, `subscriber id`, `insurance id`). When two recognisers match the same text
the longest wins.

Two changes can break an existing policy:

- **`pii.recognizers` now rejects an id that does not exist.** An unknown id used
  to be skipped in silence, so a typo such as `tckm` quietly switched a
  recogniser off. It is now a load error naming the id.
- **A non-empty `pii.recognizers` is the complete list.** That was already how it
  behaved; it is now stated, and `pii.profile: health` adds no recogniser to it. To
  run the health recognisers beside others, list them or leave the list empty. The
  profile's extra keywords for the `tckn` and `phone` recognisers (`hasta`,
  `sigortalı`, `faks`...) still apply when those two are in the list.

`@tunedness/mcpguard-detect`: `PiiScanConfig` takes `profile`, `ScanVerdict` takes
an optional `piiDigest`, a ruleset takes an optional `pii` section, and
`CompiledRuleset` an optional `pii`. A scan that asks for the health profile
against a ruleset without that section throws `PiiDataMissingError`.
