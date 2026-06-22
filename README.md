# OPRCF — OSINT Personal Risk Classification Framework

A reference implementation of the three-phase personal-risk classification
pipeline specified in **Chapter 2** of the research report *The OSINT Personal
Risk Classification Framework* (ISU 520196).

OPRCF transforms five categories of publicly observable OSINT signals into a
single normalised **Risk Index (0–100)**, adjusted for user archetype and
ongoing behavioural amplification, and classifies the result into one of four
risk tiers (Low / Moderate / High / Critical). Every assessment also returns a
per-surface breakdown, the triggered critical flags, and a ranked list of the
top-three prioritised remediation actions.

> ⚠️ **Calibration status — read this first.**
> The archetype weighting coefficients and the amplification factors in this
> implementation are **reasoned initial estimates** derived from the
> threat-model analysis of Chapter 1 (report **Section 2.8**, Limitation 1).
> They are **NOT empirically validated values.** A formal expert-elicitation
> exercise — constructing Analytic Hierarchy Process (AHP) pairwise-comparison
> matrices and computing consistency ratios — is required before the
> coefficients can be regarded as calibrated. The Risk Index should be read as
> a measure of **exposure susceptibility**, not as a calibrated probability of
> harm.

---

## Requirements

- **Python 3.8+**
- **Standard library only** — no external dependencies, no install step.

## Files

| File             | Purpose                                                        |
|------------------|----------------------------------------------------------------|
| `oprcf.py`       | Core module: `assess(profile) -> RiskReport`, constants, CLI.  |
| `demo.py`        | Runs the three case studies + a synthetic exposure spread.     |
| `test_oprcf.py`  | Unit tests (run with `unittest` or `pytest`).                  |
| `README.md`      | This file.                                                     |

## Running

### Demonstration

```bash
python demo.py
```

Prints a comparison table for the three documented case studies from
Section 2.6 (McAfee EXIF, Strava heatmap, Advertising Identifier) and a
low-to-critical spread of synthetic profiles (Section 2.4), followed by the
full detailed report for the Section 2.3 worked example.

### Command-line interface (single assessment)

```bash
python oprcf.py --archetype corporate_employee \
    --social-media 0.6 --public-records 0.7 --mobile-footprint 0.8 \
    --breach-hit --cross-platform-match \
    --location-frequency 2 --linkability --routine-disclosure --graph-density 2
```

Or load a profile from JSON (field names match the `Profile` dataclass):

```bash
python oprcf.py --archetype high_risk_individual --json profile.json
```

```jsonc
// profile.json
{
  "archetype": "high_risk_individual",
  "exif_gps": true
}
```

Run `python oprcf.py --help` for the full flag list.

### Library use

```python
from oprcf import Archetype, Profile, assess

report = assess(Profile(archetype=Archetype.GENERAL_CIVILIAN, breach_hit=True))
print(report.risk_index, report.risk_tier.value)   # 60.0 High
print(report.render())
```

### Tests

```bash
python -m unittest test_oprcf -v     # stdlib
# or
pytest test_oprcf.py                  # if pytest is installed
```

Coverage includes each phase, the confirmed-breach floor, the EXIF GPS
critical flag, the cross-surface correlation amplification trigger, the
tier-boundary cases, and the Section 2.3 worked example end-to-end.

---

## The pipeline (report Chapter 2)

### Phase 1 — Signal Collection & Taxonomy Scoring (Table 2.1)

Five surfaces, each scored `0.0–1.0`:

| Surface           | Baseline weight | Sub-signal scoring (Table 2.1)                                   |
|-------------------|-----------------|------------------------------------------------------------------|
| Breach Database   | 0.30            | Confirmed hit → surface 1.0, Risk-Index floor.                   |
| Social Media      | 0.25            | Scaled SOCMINT score; cross-platform match (3+) flagged.        |
| Public Records    | 0.20            | Each confirmed aggregator listing adds **0.2**.                  |
| Mobile Footprint  | 0.20            | ADID not reset **1.0**, default hostname **0.7**, Wi-Fi probe **0.5** (summed, clamped). |
| File Metadata     | 0.05 → **0.30** | Tiered: EXIF GPS **1.0** > doc author **0.5** > device model **0.2**. GPS → High floor. |

A **cross-surface correlation amplification** factor of **×1.2** (capped at
100) is applied when **three or more** surfaces return a non-zero score.

### Phase 2 — Archetype-Based Risk Weighting (Table 2.2)

Each surface score is multiplied by the selected archetype's coefficient and
clamped to `[0, 1]`:

| Archetype                | Coefficients (unlisted surfaces = ×1.0)                       |
|--------------------------|---------------------------------------------------------------|
| 1 — General Civilian     | Breach ×1.5, Social ×1.0                                       |
| 2 — Corporate Employee   | Public Records ×1.5, Mobile Footprint ×1.3                     |
| 3 — High-Risk Individual | **All five surfaces ×2.0**; BAI multiplier 2.0; Moderate floor |

> Archetype selection is a deliberate, functional classification of the user's
> threat context — **not** self-assessed risk tolerance. When uncertain,
> select the higher archetype to avoid underestimating exposure (Section 2.2.2).

### Phase 3 — Behavioural Amplification & Final Risk Index (Table 2.3, eq. 1)

The **Behavioural Amplification Index (BAI)** is the weighted average of four
behavioural variables:

| Variable                 | Input        | Weight |
|--------------------------|--------------|--------|
| Location frequency       | 0–3 (÷3)     | 0.35   |
| Cross-platform linkability | boolean    | 0.30   |
| Routine disclosure       | boolean      | 0.20   |
| Graph density            | 0–2 (÷2)     | 0.15   |

```
Final Risk Index = min(100, Adjusted Risk Index
                              × (1 + BAI × BAI_Multiplier)   # eq. (1)
                              × band_multiplier)             # Table 2.3 bands
```

`BAI_Multiplier` is 2.0 for Archetype 3 and 1.0 otherwise. The band multiplier
is ×1.3 when BAI > 0.6 and ×1.5 when BAI > 0.8. Routine disclosure adds a flat
**+10** points before classification.

**Tiers:** Low `0–24.9` · Moderate `25–49.9` · High `50–74.9` · Critical
`75–100`.

---

## Reconciliation notes (report self-inconsistencies)

Chapter 2's tables and prose disagree in five places. Each was resolved to
match the report's own **reference output in Section 2.3**, and is documented
in `oprcf.py` at the relevant constant:

1. **Mobile Footprint baseline weight** — Table 2.1's column shows `0.25`, but
   the Section 2.2.1 prose lists `0.20` (a set that sums cleanly to unity).
   → **0.20 adopted.**
2. **Confirmed-breach floor** — `60.0` (Table 2.1 + Section 2.3 worked example)
   vs `50.0` (Phase 3 tier prose). → **60.0 adopted** (it lies inside the High
   tier, consistent with "minimum High").
3. **BAI application mechanism** — equation (1)'s `(1 + BAI × multiplier)` vs
   Table 2.3's discrete band multipliers (×1.3 / ×1.5). → **both applied.**
4. **File-Metadata GPS escalation** — when File Metadata escalates from `0.05`
   to `0.30`, the remaining four weights are **renormalised** so the five
   weights still sum to `1.0`.
5. **Social-surface "amplification effects"** — the cross-platform-match ×1.5
   and the linkability/graph +0.2/+0.15 elevations are surfaced as **warning
   flags** rather than numeric surface modifications, because the report's
   reference output (Section 2.3) prints the social surface unmodified. The
   constants remain defined to match Tables 2.1/2.3; the behavioural inputs
   still feed the Phase 3 BAI computation.

These choices reproduce the report's reference output exactly: Risk Index
**100.0**, tier **Critical**, BAI **0.883**, with the documented per-surface
breakdown and top-three remediation order.

---

## Ethics & intended use (report Section 2.9)

OPRCF is a **defensive, consented, self-directed** privacy instrument. It is
intended for first-person assessment or for an advisor acting with the
subject's explicit consent. It consumes only already-public signals and
introduces no new collection capability; its contribution is classification
and prioritisation, paired with concrete remediation actions. Applying it to a
non-consenting third party would be an out-of-scope, dual-use misuse. Any
deployment must comply with the applicable data-protection law of its
jurisdiction.
