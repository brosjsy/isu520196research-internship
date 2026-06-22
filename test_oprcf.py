"""Unit tests for the OPRCF reference implementation.

Runs under either ``unittest`` (``python -m unittest``) or ``pytest``.
Coverage: each of the three phases, the confirmed-breach floor, the EXIF GPS
critical flag, the cross-surface correlation amplification trigger, and the
tier-boundary cases.
"""

import math
import unittest

import oprcf
from oprcf import (
    Archetype,
    Profile,
    RiskTier,
    Surface,
    assess,
    bai_band_multiplier,
    classify_tier,
    compute_bai,
    phase1_surface_scores,
    phase1_weights,
    phase2_adjusted_scores,
)


# ---------------------------------------------------------------------
# Phase 1 - Signal Collection & Taxonomy Scoring
# ---------------------------------------------------------------------
class TestPhase1(unittest.TestCase):
    def test_breach_hit_sets_surface_to_one(self):
        scores, flags = phase1_surface_scores(
            Profile(archetype=Archetype.GENERAL_CIVILIAN, breach_hit=True))
        self.assertEqual(scores[Surface.BREACH], 1.0)
        self.assertIn("confirmed breach hit", flags)

    def test_public_records_passthrough(self):
        scores, _ = phase1_surface_scores(
            Profile(archetype=Archetype.GENERAL_CIVILIAN, public_records=0.6))
        self.assertAlmostEqual(scores[Surface.PUBLIC_RECORDS], 0.6)

    def test_file_metadata_tiered(self):
        # Tiered (Table 2.1 Step 4): author (0.5) outranks device (0.2).
        scores, _ = phase1_surface_scores(Profile(
            archetype=Archetype.GENERAL_CIVILIAN,
            doc_author=True, device_model=True))
        self.assertAlmostEqual(scores[Surface.FILE_METADATA], 0.5)
        # Device model only -> 0.2.
        scores, _ = phase1_surface_scores(Profile(
            archetype=Archetype.GENERAL_CIVILIAN, device_model=True))
        self.assertAlmostEqual(scores[Surface.FILE_METADATA], 0.2)

    def test_public_records_aggregators(self):
        # Each confirmed aggregator adds 0.2 (Table 2.1 Step 3).
        scores, _ = phase1_surface_scores(Profile(
            archetype=Archetype.GENERAL_CIVILIAN, aggregator_listings=3))
        self.assertAlmostEqual(scores[Surface.PUBLIC_RECORDS], 0.6)

    def test_adid_forces_mobile_to_one(self):
        scores, flags = phase1_surface_scores(Profile(
            archetype=Archetype.GENERAL_CIVILIAN, adid_not_reset=True,
            mobile_footprint=0.2))
        self.assertEqual(scores[Surface.MOBILE_FOOTPRINT], 1.0)
        self.assertIn("ADID not reset (identity anchor)", flags)

    def test_mobile_subsignals_summed(self):
        # Hostname 0.7 + Wi-Fi 0.5 = 1.2 -> normalised (clamped) to 1.0.
        scores, _ = phase1_surface_scores(Profile(
            archetype=Archetype.GENERAL_CIVILIAN,
            default_hostname=True, wifi_probe=True))
        self.assertEqual(scores[Surface.MOBILE_FOOTPRINT], 1.0)
        # Hostname only -> 0.7.
        scores, _ = phase1_surface_scores(Profile(
            archetype=Archetype.GENERAL_CIVILIAN, default_hostname=True))
        self.assertAlmostEqual(scores[Surface.MOBILE_FOOTPRINT], 0.7)

    def test_baseline_weights_sum_to_unity(self):
        scores = {s: 0.0 for s in Surface}
        weights = phase1_weights(scores)
        self.assertAlmostEqual(sum(weights.values()), 1.0)

    def test_gps_weight_escalation_renormalises(self):
        scores = {s: 0.0 for s in Surface}
        scores[Surface.FILE_METADATA] = 1.0  # GPS present
        weights = phase1_weights(scores)
        self.assertAlmostEqual(weights[Surface.FILE_METADATA],
                               oprcf.FILE_METADATA_GPS_WEIGHT)
        # The five weights still sum to unity after escalation.
        self.assertAlmostEqual(sum(weights.values()), 1.0)
        # Breach keeps its proportional share of the remaining 0.70.
        expected_breach = 0.30 / 0.95 * (1.0 - oprcf.FILE_METADATA_GPS_WEIGHT)
        self.assertAlmostEqual(weights[Surface.BREACH], expected_breach)


# ---------------------------------------------------------------------
# Phase 2 - Archetype-Based Risk Weighting
# ---------------------------------------------------------------------
class TestPhase2(unittest.TestCase):
    def test_civilian_breach_coefficient(self):
        adjusted = phase2_adjusted_scores(
            {Surface.BREACH: 0.5, Surface.SOCIAL_MEDIA: 0.4,
             Surface.PUBLIC_RECORDS: 0.0, Surface.FILE_METADATA: 0.0,
             Surface.MOBILE_FOOTPRINT: 0.0},
            Archetype.GENERAL_CIVILIAN)
        # Breach x1.5 (Table 2.2): 0.5 -> 0.75
        self.assertAlmostEqual(adjusted[Surface.BREACH], 0.75)
        # Social x1.0 (default): unchanged
        self.assertAlmostEqual(adjusted[Surface.SOCIAL_MEDIA], 0.4)

    def test_corporate_public_and_mobile(self):
        adjusted = phase2_adjusted_scores(
            {Surface.PUBLIC_RECORDS: 0.7, Surface.MOBILE_FOOTPRINT: 0.8,
             Surface.SOCIAL_MEDIA: 0.0, Surface.BREACH: 0.0,
             Surface.FILE_METADATA: 0.0},
            Archetype.CORPORATE_EMPLOYEE)
        # 0.7 x1.5 = 1.05 -> clamped to 1.0; 0.8 x1.3 = 1.04 -> 1.0
        self.assertEqual(adjusted[Surface.PUBLIC_RECORDS], 1.0)
        self.assertEqual(adjusted[Surface.MOBILE_FOOTPRINT], 1.0)

    def test_high_risk_doubles_all_surfaces(self):
        adjusted = phase2_adjusted_scores(
            {s: 0.3 for s in Surface}, Archetype.HIGH_RISK_INDIVIDUAL)
        # 0.3 x2.0 = 0.6 for every surface
        for s in Surface:
            self.assertAlmostEqual(adjusted[s], 0.6)

    def test_surface_ceiling_enforced(self):
        adjusted = phase2_adjusted_scores(
            {s: 0.9 for s in Surface}, Archetype.HIGH_RISK_INDIVIDUAL)
        for s in Surface:
            self.assertEqual(adjusted[s], 1.0)  # 0.9 x2 -> capped at 1.0


# ---------------------------------------------------------------------
# Phase 3 - Behavioural Amplification Index
# ---------------------------------------------------------------------
class TestPhase3(unittest.TestCase):
    def test_bai_weighted_average(self):
        # Worked-example behavioural inputs -> BAI 0.883 (Section 2.3).
        bai = compute_bai(Profile(
            archetype=Archetype.CORPORATE_EMPLOYEE,
            location_frequency=2, cross_platform_linkability=True,
            routine_disclosure=True, graph_density=2))
        self.assertAlmostEqual(bai, 0.8833333, places=5)

    def test_bai_zero_when_no_behaviour(self):
        self.assertEqual(
            compute_bai(Profile(archetype=Archetype.GENERAL_CIVILIAN)), 0.0)

    def test_bai_band_multiplier(self):
        self.assertEqual(bai_band_multiplier(0.5), 1.0)
        self.assertEqual(bai_band_multiplier(0.61), 1.3)   # > 0.6
        self.assertEqual(bai_band_multiplier(0.85), 1.5)   # > 0.8
        # Boundaries are strict ("above"): exactly 0.6 / 0.8 stay in band below.
        self.assertEqual(bai_band_multiplier(0.6), 1.0)
        self.assertEqual(bai_band_multiplier(0.8), 1.3)

    def test_high_risk_bai_multiplier_is_two(self):
        self.assertEqual(
            oprcf.ARCHETYPE_BAI_MULTIPLIER[Archetype.HIGH_RISK_INDIVIDUAL], 2.0)


# ---------------------------------------------------------------------
# Critical-flag floors
# ---------------------------------------------------------------------
class TestFloors(unittest.TestCase):
    def test_breach_floor(self):
        # A lone confirmed breach must not fall below the 60.0 floor.
        report = assess(Profile(
            archetype=Archetype.GENERAL_CIVILIAN, breach_hit=True))
        self.assertGreaterEqual(report.risk_index, oprcf.BREACH_FLOOR)
        self.assertEqual(report.risk_tier, RiskTier.HIGH)

    def test_gps_critical_flag(self):
        report = assess(Profile(
            archetype=Archetype.GENERAL_CIVILIAN, exif_gps=True))
        # GPS sets the File Metadata surface to 1.0 and a High (50.0) floor.
        self.assertEqual(report.surface_scores[Surface.FILE_METADATA], 1.0)
        self.assertGreaterEqual(report.risk_index, oprcf.GPS_FLOOR)
        self.assertIn("EXIF GPS present (critical)", report.triggered_flags)

    def test_high_risk_moderate_floor(self):
        # An otherwise-empty high-risk profile still floors at Moderate.
        report = assess(Profile(archetype=Archetype.HIGH_RISK_INDIVIDUAL))
        self.assertGreaterEqual(report.risk_index,
                                oprcf.HIGH_RISK_MODERATE_FLOOR)
        self.assertEqual(report.risk_tier, RiskTier.MODERATE)


# ---------------------------------------------------------------------
# Cross-surface correlation amplification
# ---------------------------------------------------------------------
class TestCorrelationAmplification(unittest.TestCase):
    def test_two_surfaces_no_amplification(self):
        report = assess(Profile(
            archetype=Archetype.GENERAL_CIVILIAN,
            social_media=0.4, public_records=0.4))
        self.assertFalse(any("correlation amplification" in f
                             for f in report.triggered_flags))

    def test_three_surfaces_triggers_amplification(self):
        report = assess(Profile(
            archetype=Archetype.GENERAL_CIVILIAN,
            social_media=0.4, public_records=0.4, mobile_footprint=0.4))
        self.assertTrue(any("correlation amplification" in f
                            for f in report.triggered_flags))

    def test_amplification_factor_value(self):
        # Index with three equal surfaces is exactly x1.2 the un-amplified sum.
        p_two = Profile(archetype=Archetype.GENERAL_CIVILIAN,
                        social_media=0.4, public_records=0.4)
        p_three = Profile(archetype=Archetype.GENERAL_CIVILIAN,
                          social_media=0.4, public_records=0.4,
                          mobile_footprint=0.4)
        # Build the comparison manually to isolate the x1.2 factor.
        s2, _ = phase1_surface_scores(p_two)
        a2 = phase2_adjusted_scores(s2, p_two.archetype)
        w2 = phase1_weights(s2)
        base_two = sum(w2[s] * a2[s] for s in Surface) * 100.0
        s3, _ = phase1_surface_scores(p_three)
        a3 = phase2_adjusted_scores(s3, p_three.archetype)
        w3 = phase1_weights(s3)
        base_three = sum(w3[s] * a3[s] for s in Surface) * 100.0
        # base_three already includes the third surface; the report's index
        # multiplies it by 1.2. Confirm the reported index reflects that.
        self.assertAlmostEqual(
            assess(p_three).risk_index,
            round(base_three * oprcf.CORRELATION_FACTOR, 1), places=1)
        # And the two-surface case is not amplified.
        self.assertAlmostEqual(assess(p_two).risk_index,
                               round(base_two, 1), places=1)


# ---------------------------------------------------------------------
# Tier classification boundaries (Section 2.2.3)
# ---------------------------------------------------------------------
class TestTierBoundaries(unittest.TestCase):
    def test_classify_tier_boundaries(self):
        self.assertEqual(classify_tier(0.0), RiskTier.LOW)
        self.assertEqual(classify_tier(24.9), RiskTier.LOW)
        self.assertEqual(classify_tier(25.0), RiskTier.MODERATE)
        self.assertEqual(classify_tier(49.9), RiskTier.MODERATE)
        self.assertEqual(classify_tier(50.0), RiskTier.HIGH)
        self.assertEqual(classify_tier(74.9), RiskTier.HIGH)
        self.assertEqual(classify_tier(75.0), RiskTier.CRITICAL)
        self.assertEqual(classify_tier(100.0), RiskTier.CRITICAL)


# ---------------------------------------------------------------------
# End-to-end - the report's worked example (Section 2.3)
# ---------------------------------------------------------------------
class TestWorkedExample(unittest.TestCase):
    def test_section_2_3_reference_output(self):
        report = assess(Profile(
            archetype=Archetype.CORPORATE_EMPLOYEE,
            social_media=0.6, public_records=0.7, mobile_footprint=0.8,
            breach_hit=True, cross_platform_match=True,
            location_frequency=2, cross_platform_linkability=True,
            routine_disclosure=True, graph_density=2))
        self.assertEqual(report.risk_index, 100.0)
        self.assertEqual(report.risk_tier, RiskTier.CRITICAL)
        self.assertEqual(report.bai_score, 0.883)
        # Adjusted breakdown matches the report's reference output.
        self.assertAlmostEqual(report.adjusted_scores[Surface.SOCIAL_MEDIA], 0.6)
        self.assertEqual(report.adjusted_scores[Surface.PUBLIC_RECORDS], 1.0)
        self.assertEqual(report.adjusted_scores[Surface.MOBILE_FOOTPRINT], 1.0)
        self.assertEqual(report.adjusted_scores[Surface.FILE_METADATA], 0.0)
        # Remediation order: breach, data brokers, ADID.
        self.assertEqual(report.remediation[0],
                         "rotate breached passwords and enable MFA")
        self.assertEqual(report.remediation[1],
                         "submit data-broker opt-out requests")
        self.assertEqual(report.remediation[2],
                         "reset the Advertising Identifier")

    def test_index_never_exceeds_cap(self):
        report = assess(Profile(
            archetype=Archetype.HIGH_RISK_INDIVIDUAL,
            social_media=1.0, public_records=1.0, mobile_footprint=1.0,
            breach_hit=True, exif_gps=True, adid_not_reset=True,
            location_frequency=3, cross_platform_linkability=True,
            routine_disclosure=True, graph_density=2))
        self.assertLessEqual(report.risk_index, 100.0)


# ---------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------
class TestValidation(unittest.TestCase):
    def test_rejects_out_of_range_surface(self):
        with self.assertRaises(ValueError):
            Profile(archetype=Archetype.GENERAL_CIVILIAN, social_media=1.5)

    def test_rejects_bad_archetype(self):
        with self.assertRaises(TypeError):
            Profile(archetype="civilian")  # type: ignore[arg-type]

    def test_rejects_out_of_range_behaviour(self):
        with self.assertRaises(ValueError):
            Profile(archetype=Archetype.GENERAL_CIVILIAN, graph_density=3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
