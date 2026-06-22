"""OPRCF - OSINT Personal Risk Classification Framework
=======================================================

Reference implementation of the three-phase risk-classification pipeline
specified in Chapter 2 of the research report *The OSINT Personal Risk
Classification Framework* (ISU 520196).

The pipeline is a Collect -> Weight -> Amplify methodology:

    Phase 1  Signal Collection & Taxonomy Scoring   (Table 2.1)
    Phase 2  Archetype-Based Risk Weighting          (Table 2.2)
    Phase 3  Behavioural Amplification & Risk Index   (Table 2.3, eq. 1)

Standard library only, Python 3.8+.

------------------------------------------------------------------------
IMPORTANT - calibration status
------------------------------------------------------------------------
The archetype coefficients and amplification factors encoded below are the
report author's *reasoned initial estimates* derived from the threat-model
analysis of Chapter 1 (see report Section 2.8, Limitation 1). They are NOT
empirically validated values. A formal expert-elicitation exercise (AHP
pairwise-comparison matrices with consistency ratios) is required before the
coefficients can be regarded as calibrated. Read the Risk Index as a measure
of *exposure susceptibility*, not as a probability of harm.

------------------------------------------------------------------------
Reconciliation notes (report self-inconsistencies, resolved here)
------------------------------------------------------------------------
The report's tables and prose disagree in four places. Each resolution is
documented at the relevant constant below and summarised in README.md:

  * Mobile Footprint baseline weight: Table 2.1 column = 0.25, p.36 prose =
    0.20. -> 0.20 adopted (the p.36 set sums to unity and matches the
    worked example in Section 2.3).
  * Confirmed-breach floor: 60.0 (Table 2.1 / Section 2.3) vs 50.0 (Phase 3
    tier prose). -> 60.0 adopted (stated in two places incl. the worked
    trace; 60 lies inside the High tier, consistent with "minimum High").
  * BAI application: eq. 1 multiplier vs Table 2.3 discrete band multipliers.
    -> BOTH applied (author's decision): eq. 1 factor (1 + BAI*mult) is
    multiplied by the band factor (x1.3 above 0.6, x1.5 above 0.8).
  * File-Metadata GPS escalation (0.05 -> 0.30): the remaining four weights
    are renormalised so the five weights still sum to 1.0.
  * Social-surface "amplification effects" (cross-platform match x1.5,
    linkability +0.2, graph-density +0.15): the report's own reference output
    (Section 2.3) prints the social surface UNMODIFIED by these effects, so
    they are surfaced as warning flags rather than numeric surface
    elevations. The constants remain defined below to match Tables 2.1/2.3.
    (The behavioural inputs still feed the BAI computation in Phase 3.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple


# =====================================================================
# Enumerations
# =====================================================================
class Surface(Enum):
    """The five OSINT digital surfaces (Table 2.1)."""
    SOCIAL_MEDIA = "social_media"
    BREACH = "breach"
    PUBLIC_RECORDS = "public_records"
    FILE_METADATA = "file_metadata"
    MOBILE_FOOTPRINT = "mobile_footprint"


class Archetype(Enum):
    """User archetypes (Table 2.2)."""
    GENERAL_CIVILIAN = "general_civilian"        # Archetype 1
    CORPORATE_EMPLOYEE = "corporate_employee"    # Archetype 2
    HIGH_RISK_INDIVIDUAL = "high_risk_individual"  # Archetype 3


class RiskTier(Enum):
    """Four-tier classification (Section 2.2.3)."""
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    CRITICAL = "Critical"


# =====================================================================
# PHASE 1 constants - Signal Collection & Taxonomy Scoring (Table 2.1)
# =====================================================================
# Baseline per-surface weights in the Risk Index. Source: Section 2.2.1
# prose (p.36), which lists weights summing to unity. (Table 2.1's column
# shows Mobile = 0.25; the prose value 0.20 is adopted - see module header.)
BASELINE_WEIGHTS: Dict[Surface, float] = {
    Surface.BREACH: 0.30,           # Table 2.1 / p.36 - primary identity anchor
    Surface.SOCIAL_MEDIA: 0.25,     # Table 2.1 / p.36
    Surface.PUBLIC_RECORDS: 0.20,   # Table 2.1 / p.36
    Surface.MOBILE_FOOTPRINT: 0.20,  # p.36 prose (Table 2.1 col. shows 0.25)
    Surface.FILE_METADATA: 0.05,    # Table 2.1 / p.36 - baseline
}

# File Metadata escalates to this weight when EXIF GPS is confirmed present.
# Source: Section 2.2.1, p.36 ("escalates to 0.30 when GPS coordinates are
# confirmed present"). The other four weights are renormalised afterwards.
FILE_METADATA_GPS_WEIGHT: float = 0.30  # Table 2.1 / Section 2.2.1

# Cross-surface correlation amplification. Source: Section 2.2.1 (p.36-37):
# "When three or more surfaces return a non-zero score, the total
# pre-weighting index is multiplied by 1.2, capped at 100.0." Grounded in
# the unicity result of de Montjoye et al. (2013).
CORRELATION_FACTOR: float = 1.2                 # Section 2.2.1
CORRELATION_MIN_SURFACES: int = 3               # Section 2.2.1
CORRELATION_CAP: float = 100.0                  # Section 2.2.1

# Phase 1 Social sub-signal: a cross-platform username match (3+ platforms)
# multiplies the social surface score. Source: Table 2.1 Step 1
# ("Cross-platform username match triggers weight multiplier x1.5").
SOCIAL_CROSS_PLATFORM_MULTIPLIER: float = 1.5   # Table 2.1, Step 1

# File Metadata sub-signal scores. Source: Table 2.1, Step 4.
FILE_GPS_SCORE: float = 1.0          # Table 2.1 Step 4 - critical flag
FILE_AUTHOR_SCORE: float = 0.5       # Table 2.1 Step 4 - document author match
FILE_DEVICE_SCORE: float = 0.2       # Table 2.1 Step 4 - device model only

# Confirmed-breach floor on the final Risk Index. Source: Table 2.1 Step 2
# and Section 2.3 worked example ("Single confirmed hit sets floor at 60.0").
BREACH_FLOOR: float = 60.0           # Table 2.1 Step 2 / Section 2.3

# EXIF GPS critical flag sets a High-tier floor. Source: Section 2.6.2
# Scenario A ("setting the risk floor at High").
GPS_FLOOR: float = 50.0              # Section 2.6.2 (High-tier floor)


# =====================================================================
# PHASE 2 constants - Archetype-Based Risk Weighting (Table 2.2)
# =====================================================================
# Per-(archetype, surface) coefficients. Surfaces not listed for an
# archetype default to 1.0 (DEFAULT_COEFFICIENT). Source: Table 2.2.
DEFAULT_COEFFICIENT: float = 1.0

ARCHETYPE_COEFFICIENTS: Dict[Archetype, Dict[Surface, float]] = {
    # Archetype 1 - General Civilian (Table 2.2)
    Archetype.GENERAL_CIVILIAN: {
        Surface.BREACH: 1.5,         # Table 2.2 - email-based credential attacks
        Surface.SOCIAL_MEDIA: 1.0,   # Table 2.2 - standard social-engineering risk
        # Public Records, File Metadata, Mobile Footprint -> default 1.0
    },
    # Archetype 2 - Corporate Employee (Table 2.2)
    Archetype.CORPORATE_EMPLOYEE: {
        Surface.PUBLIC_RECORDS: 1.5,   # Table 2.2 - corporate-intelligence targeting
        Surface.MOBILE_FOOTPRINT: 1.3,  # Table 2.2 - business-traveller ADID tracking
        # Breach, Social Media, File Metadata -> default 1.0
    },
    # Archetype 3 - High-Risk Individual (Table 2.2): all five surfaces x2.0
    Archetype.HIGH_RISK_INDIVIDUAL: {
        Surface.SOCIAL_MEDIA: 2.0,
        Surface.BREACH: 2.0,
        Surface.PUBLIC_RECORDS: 2.0,
        Surface.FILE_METADATA: 2.0,
        Surface.MOBILE_FOOTPRINT: 2.0,
    },
}

# Per-surface ceiling after archetype multiplication. Source: Table 2.2
# ("multiplied by ... capped at 1.0 per surface") and Section 2.2.2
# ("re-normalized to the 0.0 to 1.0 range").
SURFACE_CEILING: float = 1.0         # Table 2.2

# Archetype 3 risk-tier floor. Source: Table 2.2 ("Risk tier floor set at
# Moderate regardless of individual scores").
HIGH_RISK_MODERATE_FLOOR: float = 25.0  # Table 2.2 (Moderate floor)


# =====================================================================
# PHASE 3 constants - Behavioural Amplification Index (Table 2.3, eq. 1)
# =====================================================================
# BAI variable computation weights (sum to 1.0). Source: Table 2.3.
BAI_WEIGHT_LOCATION: float = 0.35     # Table 2.3 Step 1 - location frequency
BAI_WEIGHT_LINKABILITY: float = 0.30  # Table 2.3 Step 2 - cross-platform linkability
BAI_WEIGHT_ROUTINE: float = 0.20      # Table 2.3 Step 3 - routine disclosure
BAI_WEIGHT_GRAPH: float = 0.15        # Table 2.3 Step 4 - graph density

# Normalisation divisors for the integer BAI inputs. Source: Table 2.3.
BAI_LOCATION_MAX: int = 3             # Table 2.3 Step 1 (0..3, divide by 3)
BAI_GRAPH_MAX: int = 2               # Table 2.3 Step 4 (0..2, divide by 2)

# Discrete BAI band multipliers. Source: Table 2.3 Step 1 amplification
# effect ("BAI above 0.6 applies x1.3 multiplier ... above 0.8 applies x1.5").
BAI_BAND_LOW_THRESHOLD: float = 0.6   # Table 2.3
BAI_BAND_HIGH_THRESHOLD: float = 0.8  # Table 2.3
BAI_BAND_LOW_MULTIPLIER: float = 1.3  # Table 2.3 (0.6 < BAI <= 0.8)
BAI_BAND_HIGH_MULTIPLIER: float = 1.5  # Table 2.3 (BAI > 0.8)

# Behavioural surface-score elevations applied to the Social Media surface.
# Source: Table 2.3 Step 2 (linkability "+0.2") and Step 4 (graph density 2
# "+0.15").
BAI_LINKABILITY_SOCIAL_BONUS: float = 0.20  # Table 2.3 Step 2
BAI_GRAPH_SOCIAL_BONUS: float = 0.15        # Table 2.3 Step 4
BAI_GRAPH_FULLY_PUBLIC: int = 2             # Table 2.3 Step 4 (density == 2)

# Routine disclosure adds a flat increment to the final index. Source:
# Table 2.3 Step 3 ("Adds 10 points to final Risk Index before tier
# classification").
ROUTINE_DISCLOSURE_POINTS: float = 10.0     # Table 2.3 Step 3

# Per-archetype BAI multiplier in eq. (1). Source: Section 2.2.3
# ("For Archetype 3, the BAI Multiplier is 2.0 ... For Archetypes 1 and 2,
# the BAI Multiplier is 1.0").
ARCHETYPE_BAI_MULTIPLIER: Dict[Archetype, float] = {
    Archetype.GENERAL_CIVILIAN: 1.0,        # Section 2.2.3
    Archetype.CORPORATE_EMPLOYEE: 1.0,      # Section 2.2.3
    Archetype.HIGH_RISK_INDIVIDUAL: 2.0,    # Section 2.2.3 / Table 2.2
}


# =====================================================================
# Final classification constants (Section 2.2.3)
# =====================================================================
INDEX_CAP: float = 100.0             # Section 2.2.3 - index ceiling
# Tier boundaries: Low 0-24.9, Moderate 25-49.9, High 50-74.9,
# Critical 75-100. Source: Section 2.2.3.
TIER_MODERATE_THRESHOLD: float = 25.0   # Section 2.2.3
TIER_HIGH_THRESHOLD: float = 50.0       # Section 2.2.3
TIER_CRITICAL_THRESHOLD: float = 75.0   # Section 2.2.3


# =====================================================================
# Remediation control points (Section 2.2.3 / Section 2.6 case studies)
# =====================================================================
# Each surface maps to a concrete remediation action (a control point the
# user can act on directly). Source: Section 2.3 worked example and the
# Section 2.6 case-study remediation outputs.
REMEDIATION_ACTIONS: Dict[Surface, str] = {
    Surface.BREACH: "rotate breached passwords and enable MFA",
    Surface.PUBLIC_RECORDS: "submit data-broker opt-out requests",
    Surface.MOBILE_FOOTPRINT: "reset the Advertising Identifier",
    Surface.FILE_METADATA: "strip EXIF metadata and disable camera location",
    Surface.SOCIAL_MEDIA: "restrict geotagging and lock down profile visibility",
}


# =====================================================================
# Input / output dataclasses
# =====================================================================
@dataclass
class Profile:
    """Observable OSINT inputs for a single subject.

    Surface base scores (social_media, public_records, mobile_footprint) are
    continuous 0.0-1.0 values as specified in Table 2.1. The breach and file
    surfaces are driven by their binary/critical sub-signals. Behavioural
    inputs feed the Phase 3 BAI computation (Table 2.3).
    """
    archetype: Archetype

    # --- Phase 1 surface base scores (0.0 - 1.0) ---
    social_media: float = 0.0
    public_records: float = 0.0
    mobile_footprint: float = 0.0

    # --- Phase 1 breach surface (Table 2.1 Step 2) ---
    breach_hit: bool = False             # confirmed breach -> surface 1.0, floor

    # --- Phase 1 file-metadata sub-signals (Table 2.1 Step 4) ---
    exif_gps: bool = False               # GPS present -> surface 1.0, critical flag
    doc_author: bool = False             # document author exposed -> 0.5
    device_model: bool = False           # device model visible -> 0.2

    # --- Phase 1 social / mobile flags ---
    cross_platform_match: bool = False   # username match on 3+ platforms (Step 1)
    adid_not_reset: bool = False         # identity-anchor flag (Step 5)

    # --- Phase 3 behavioural inputs (Table 2.3) ---
    location_frequency: int = 0          # 0=never,1=weekly,2=daily,3=real-time
    cross_platform_linkability: bool = False  # name/handle on 3+ platforms
    routine_disclosure: bool = False     # posts predictable schedule/location
    graph_density: int = 0               # 0=private,1=semi-public,2=fully public

    def __post_init__(self) -> None:
        if not isinstance(self.archetype, Archetype):
            raise TypeError("archetype must be an Archetype enum member")
        for name in ("social_media", "public_records", "mobile_footprint"):
            v = getattr(self, name)
            if not 0.0 <= v <= 1.0:
                raise ValueError("%s must be within [0.0, 1.0], got %r" % (name, v))
        if not 0 <= self.location_frequency <= BAI_LOCATION_MAX:
            raise ValueError("location_frequency must be 0..3")
        if not 0 <= self.graph_density <= BAI_GRAPH_MAX:
            raise ValueError("graph_density must be 0..2")


@dataclass
class RiskReport:
    """Structured OPRCF output (Section 2.2.3)."""
    archetype: Archetype
    risk_index: float
    risk_tier: RiskTier
    bai_score: float
    surface_scores: Dict[Surface, float]      # Phase 1 raw per-surface vector
    adjusted_scores: Dict[Surface, float]     # Phase 2 archetype-adjusted vector
    triggered_flags: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)

    def render(self) -> str:
        """Render the report in the format shown in Section 2.3.

        The per-surface breakdown shows the Phase-2 archetype-adjusted
        vector, matching the reference output in the report.
        """
        s = self.adjusted_scores
        lines = [
            "OPRCF RISK REPORT",
            "Archetype       : %s" % self.archetype.value,
            "Risk Index      : %.1f / 100" % self.risk_index,
            "Risk Tier       : %s" % self.risk_tier.value,
            "BAI score       : %.3f" % self.bai_score,
            "Per-surface breakdown:",
            "  social_media   : %.3f   breach         : %.3f   public_records : %.3f"
            % (s[Surface.SOCIAL_MEDIA], s[Surface.BREACH], s[Surface.PUBLIC_RECORDS]),
            "  file_metadata  : %.3f   mobile_footprint: %.3f"
            % (s[Surface.FILE_METADATA], s[Surface.MOBILE_FOOTPRINT]),
            "Triggered flags: %s"
            % ("; ".join(self.triggered_flags) if self.triggered_flags else "none"),
            "Top remediation: %s"
            % ("; ".join("(%d) %s" % (i + 1, a)
                         for i, a in enumerate(self.remediation))
               if self.remediation else "none"),
        ]
        return "\n".join(lines)


# =====================================================================
# Phase 1 - Signal Collection & Taxonomy Scoring
# =====================================================================
def _clamp(value: float, ceiling: float = 1.0) -> float:
    return max(0.0, min(ceiling, value))


def phase1_surface_scores(profile: Profile) -> Tuple[Dict[Surface, float], List[str]]:
    """Compute the raw per-surface score vector and triggered flags (Table 2.1)."""
    flags: List[str] = []

    # --- Social Media (Step 1) ---
    # The social surface score is the observed base value. The cross-platform
    # match (Table 2.1, x1.5) and the behavioural elevations (Table 2.3,
    # +0.2 / +0.15) are surfaced as warning flags rather than numeric
    # modifications, matching the report's reference output (Section 2.3).
    social = _clamp(profile.social_media)
    if profile.cross_platform_match:
        flags.append("cross-platform match (3+)")
    if profile.cross_platform_linkability:
        flags.append("username enumeration warning")
    if profile.graph_density == BAI_GRAPH_FULLY_PUBLIC:
        flags.append("fully-public social graph (secondary-target warning)")

    # --- Breach Database (Step 2) ---
    breach = 1.0 if profile.breach_hit else 0.0
    if profile.breach_hit:
        flags.append("confirmed breach hit")

    # --- Public Records (Step 3) ---
    public_records = _clamp(profile.public_records)

    # --- File Metadata (Step 4) ---
    if profile.exif_gps:
        file_metadata = FILE_GPS_SCORE          # critical flag -> 1.0
        flags.append("EXIF GPS present (critical)")
    else:
        file_metadata = _clamp(
            (FILE_AUTHOR_SCORE if profile.doc_author else 0.0)
            + (FILE_DEVICE_SCORE if profile.device_model else 0.0)
        )

    # --- Mobile Footprint (Step 5) ---
    mobile = profile.mobile_footprint
    if profile.adid_not_reset:
        mobile = 1.0                             # identity-anchor -> surface 1.0
        flags.append("ADID not reset (identity anchor)")
    mobile = _clamp(mobile)

    scores = {
        Surface.SOCIAL_MEDIA: social,
        Surface.BREACH: breach,
        Surface.PUBLIC_RECORDS: public_records,
        Surface.FILE_METADATA: file_metadata,
        Surface.MOBILE_FOOTPRINT: mobile,
    }
    return scores, flags


def phase1_weights(scores: Dict[Surface, float]) -> Dict[Surface, float]:
    """Return per-surface index weights, escalating + renormalising for GPS.

    When EXIF GPS pushes the File Metadata surface to 1.0, its weight rises
    from 0.05 to 0.30 (Section 2.2.1); the remaining four weights are then
    renormalised so the five weights still sum to 1.0.
    """
    weights = dict(BASELINE_WEIGHTS)
    if scores[Surface.FILE_METADATA] >= FILE_GPS_SCORE:
        weights[Surface.FILE_METADATA] = FILE_METADATA_GPS_WEIGHT
        others = [s for s in weights if s is not Surface.FILE_METADATA]
        remaining = 1.0 - FILE_METADATA_GPS_WEIGHT
        base_sum = sum(BASELINE_WEIGHTS[s] for s in others)
        for s in others:
            weights[s] = BASELINE_WEIGHTS[s] / base_sum * remaining
    return weights


# =====================================================================
# Phase 2 - Archetype-Based Risk Weighting
# =====================================================================
def phase2_adjusted_scores(
    scores: Dict[Surface, float], archetype: Archetype
) -> Dict[Surface, float]:
    """Apply archetype coefficients and clamp to [0, 1] (Table 2.2)."""
    coeffs = ARCHETYPE_COEFFICIENTS[archetype]
    return {
        surface: _clamp(score * coeffs.get(surface, DEFAULT_COEFFICIENT),
                        SURFACE_CEILING)
        for surface, score in scores.items()
    }


# =====================================================================
# Phase 3 - Behavioural Amplification Index
# =====================================================================
def compute_bai(profile: Profile) -> float:
    """Weighted average of the four behavioural variables (Table 2.3)."""
    return (
        BAI_WEIGHT_LOCATION * (profile.location_frequency / BAI_LOCATION_MAX)
        + BAI_WEIGHT_LINKABILITY * (1.0 if profile.cross_platform_linkability else 0.0)
        + BAI_WEIGHT_ROUTINE * (1.0 if profile.routine_disclosure else 0.0)
        + BAI_WEIGHT_GRAPH * (profile.graph_density / BAI_GRAPH_MAX)
    )


def bai_band_multiplier(bai: float) -> float:
    """Discrete band multiplier from Table 2.3 (x1.3 above 0.6, x1.5 above 0.8)."""
    if bai > BAI_BAND_HIGH_THRESHOLD:
        return BAI_BAND_HIGH_MULTIPLIER
    if bai > BAI_BAND_LOW_THRESHOLD:
        return BAI_BAND_LOW_MULTIPLIER
    return 1.0


def classify_tier(index: float) -> RiskTier:
    """Map a 0-100 index to a risk tier (Section 2.2.3)."""
    if index >= TIER_CRITICAL_THRESHOLD:
        return RiskTier.CRITICAL
    if index >= TIER_HIGH_THRESHOLD:
        return RiskTier.HIGH
    if index >= TIER_MODERATE_THRESHOLD:
        return RiskTier.MODERATE
    return RiskTier.LOW


# =====================================================================
# Remediation
# =====================================================================
def _rank_remediation(
    adjusted: Dict[Surface, float], weights: Dict[Surface, float]
) -> List[str]:
    """Top-three remediation actions ranked by weighted surface contribution."""
    contributions = [
        (surface, weights[surface] * score)
        for surface, score in adjusted.items()
        if score > 0.0
    ]
    contributions.sort(key=lambda kv: kv[1], reverse=True)
    return [REMEDIATION_ACTIONS[surface] for surface, _ in contributions[:3]]


# =====================================================================
# Public API
# =====================================================================
def assess(profile: Profile) -> RiskReport:
    """Run the full three-phase OPRCF pipeline and return a RiskReport."""
    # ---- Phase 1: signal collection & taxonomy scoring ----
    raw_scores, flags = phase1_surface_scores(profile)
    weights = phase1_weights(raw_scores)

    # ---- Phase 2: archetype weighting ----
    adjusted = phase2_adjusted_scores(raw_scores, profile.archetype)

    # ---- Static (pre-amplification) Risk Index ----
    static_index = sum(weights[s] * adjusted[s] for s in Surface) * 100.0

    # Cross-surface correlation amplification (counts non-zero raw surfaces).
    non_zero = sum(1 for v in raw_scores.values() if v > 0.0)
    if non_zero >= CORRELATION_MIN_SURFACES:
        static_index = min(CORRELATION_CAP, static_index * CORRELATION_FACTOR)
        flags.append(
            "correlation amplification (%d surfaces, x%.1f)"
            % (non_zero, CORRELATION_FACTOR)
        )

    # ---- Phase 3: behavioural amplification ----
    bai = compute_bai(profile)
    bai_mult = ARCHETYPE_BAI_MULTIPLIER[profile.archetype]
    band_mult = bai_band_multiplier(bai)

    # eq. (1) factor AND the Table 2.3 band multiplier (both applied).
    index = static_index * (1.0 + bai * bai_mult) * band_mult

    if bai > BAI_BAND_HIGH_THRESHOLD:
        flags.append("very high behavioural amplification")
    elif bai > BAI_BAND_LOW_THRESHOLD:
        flags.append("high behavioural amplification")

    # Routine disclosure: +10 Pattern-of-Life points before classification.
    if profile.routine_disclosure:
        index += ROUTINE_DISCLOSURE_POINTS
        flags.append("public routine disclosure (+10 Pattern-of-Life)")

    # ---- Critical-flag floors ----
    if profile.breach_hit:
        index = max(index, BREACH_FLOOR)
    if profile.exif_gps:
        index = max(index, GPS_FLOOR)
    if profile.archetype is Archetype.HIGH_RISK_INDIVIDUAL:
        index = max(index, HIGH_RISK_MODERATE_FLOOR)
        flags.append("high-risk archetype (Moderate floor)")

    index = min(INDEX_CAP, index)
    tier = classify_tier(index)

    return RiskReport(
        archetype=profile.archetype,
        risk_index=round(index, 1),
        risk_tier=tier,
        bai_score=round(bai, 3),
        surface_scores=raw_scores,
        adjusted_scores=adjusted,
        triggered_flags=flags,
        remediation=_rank_remediation(adjusted, weights),
    )


# =====================================================================
# Command-line interface
# =====================================================================
def _build_arg_parser():
    import argparse

    p = argparse.ArgumentParser(
        prog="oprcf",
        description="OSINT Personal Risk Classification Framework - single assessment.",
        epilog="Archetype coefficients are reasoned initial estimates, NOT "
               "empirically validated (report Section 2.8).",
    )
    p.add_argument(
        "--archetype", "-a", required=True,
        choices=[a.value for a in Archetype],
        help="user archetype",
    )
    p.add_argument("--social-media", type=float, default=0.0,
                   help="social media surface score 0.0-1.0")
    p.add_argument("--public-records", type=float, default=0.0,
                   help="public records surface score 0.0-1.0")
    p.add_argument("--mobile-footprint", type=float, default=0.0,
                   help="mobile footprint surface score 0.0-1.0")
    p.add_argument("--breach-hit", action="store_true",
                   help="confirmed breach hit (sets breach surface 1.0 + floor)")
    p.add_argument("--exif-gps", action="store_true",
                   help="EXIF GPS present in shared images (critical flag)")
    p.add_argument("--doc-author", action="store_true",
                   help="document author name exposed")
    p.add_argument("--device-model", action="store_true",
                   help="device model visible in metadata")
    p.add_argument("--cross-platform-match", action="store_true",
                   help="username match on 3+ platforms (Phase 1 social)")
    p.add_argument("--adid-not-reset", action="store_true",
                   help="Advertising Identifier not reset (identity anchor)")
    p.add_argument("--location-frequency", type=int, default=0,
                   help="0=never,1=weekly,2=daily,3=real-time")
    p.add_argument("--linkability", action="store_true",
                   help="name/handle consistent on 3+ platforms (BAI)")
    p.add_argument("--routine-disclosure", action="store_true",
                   help="posts predictable schedule/location (BAI)")
    p.add_argument("--graph-density", type=int, default=0,
                   help="0=private,1=semi-public,2=fully public")
    p.add_argument("--json", metavar="PATH",
                   help="load a profile from a JSON file (overrides other flags)")
    return p


def profile_from_dict(data: dict) -> Profile:
    """Build a Profile from a plain dict (e.g. parsed JSON)."""
    data = dict(data)
    data["archetype"] = Archetype(data["archetype"])
    allowed = Profile.__dataclass_fields__.keys()
    return Profile(**{k: v for k, v in data.items() if k in allowed})


def main(argv=None) -> int:
    import json

    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.json:
        with open(args.json, "r", encoding="utf-8") as fh:
            profile = profile_from_dict(json.load(fh))
    else:
        profile = Profile(
            archetype=Archetype(args.archetype),
            social_media=args.social_media,
            public_records=args.public_records,
            mobile_footprint=args.mobile_footprint,
            breach_hit=args.breach_hit,
            exif_gps=args.exif_gps,
            doc_author=args.doc_author,
            device_model=args.device_model,
            cross_platform_match=args.cross_platform_match,
            adid_not_reset=args.adid_not_reset,
            location_frequency=args.location_frequency,
            cross_platform_linkability=args.linkability,
            routine_disclosure=args.routine_disclosure,
            graph_density=args.graph_density,
        )

    print(assess(profile).render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
