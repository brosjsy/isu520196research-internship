"""OPRCF demonstration driver.

Runs the three documented case studies from Section 2.6 of the report
(McAfee EXIF, Strava heatmap, Advertising Identifier de-anonymisation) plus
a spread of synthetic profiles ranging from minimal to critical exposure,
and prints a comparison table.

    python demo.py

Note: the archetype coefficients are reasoned initial estimates, NOT
empirically validated values (report Section 2.8).
"""

from typing import List, Tuple

from oprcf import Archetype, Profile, RiskReport, assess


# ---------------------------------------------------------------------
# Case studies (report Section 2.6)
# ---------------------------------------------------------------------
def case_studies() -> List[Tuple[str, Profile]]:
    """The three retrospective validation cases from Section 2.6."""
    return [
        # Scenario A - EXIF metadata exposure (John McAfee, 2012).
        # File Metadata surface: EXIF GPS present -> critical flag.
        # Modelled as an Archetype 3 (High-Risk Individual) fugitive.
        ("Case A: McAfee EXIF GPS", Profile(
            archetype=Archetype.HIGH_RISK_INDIVIDUAL,
            exif_gps=True,
        )),
        # Scenario B - Strava aggregated behavioural exposure (2018).
        # Social Media 0.7-0.9 and Mobile Footprint 0.6-0.8 with real-time
        # location posting and routine disclosure. Personnel modelled as
        # High-Risk Individuals operating inside sensitive facilities.
        ("Case B: Strava heatmap", Profile(
            archetype=Archetype.HIGH_RISK_INDIVIDUAL,
            social_media=0.8,
            mobile_footprint=0.7,
            location_frequency=3,           # real-time check-ins
            routine_disclosure=True,
            graph_density=1,
        )),
        # Scenario C - Advertising Identifier de-anonymisation (2021).
        # Mobile Footprint: ADID not reset -> surface 1.0, identity anchor.
        # Senior official modelled as an Archetype 2 (Corporate Employee).
        ("Case C: Advertising ID", Profile(
            archetype=Archetype.CORPORATE_EMPLOYEE,
            adid_not_reset=True,
            location_frequency=2,
            routine_disclosure=True,
        )),
    ]


# ---------------------------------------------------------------------
# Synthetic spread (report Section 2.4 - graduated tier behaviour)
# ---------------------------------------------------------------------
def synthetic_profiles() -> List[Tuple[str, Profile]]:
    """A low-to-critical spread illustrating the monotonic tier progression.

    Mirrors the representative distribution described in Section 2.4: a
    minimal-exposure civilian (Low), an average civilian (Moderate), the
    same civilian with an added confirmed breach (High), and a fully exposed
    profile (Critical). The exact index values in Section 2.4 (4.5 / 42.5 /
    72.1 / 100.0) are illustrative; the inputs below reproduce the same
    monotonic Low -> Moderate -> High -> Critical progression.
    """
    return [
        ("Minimal civilian", Profile(
            archetype=Archetype.GENERAL_CIVILIAN,
            social_media=0.1,
        )),
        ("Average civilian", Profile(
            archetype=Archetype.GENERAL_CIVILIAN,
            social_media=0.5, public_records=0.3, mobile_footprint=0.4,
            location_frequency=1, graph_density=1,
        )),
        ("Civilian + confirmed breach", Profile(
            archetype=Archetype.GENERAL_CIVILIAN,
            social_media=0.4, mobile_footprint=0.3, breach_hit=True,
            location_frequency=1,
        )),
        ("Exposed corporate employee", Profile(
            archetype=Archetype.CORPORATE_EMPLOYEE,
            social_media=0.6, public_records=0.7, mobile_footprint=0.8,
            breach_hit=True, cross_platform_match=True,
            location_frequency=2, cross_platform_linkability=True,
            routine_disclosure=True, graph_density=2,
        )),
        ("Fully exposed high-risk individual", Profile(
            archetype=Archetype.HIGH_RISK_INDIVIDUAL,
            social_media=0.9, public_records=0.9, mobile_footprint=0.9,
            breach_hit=True, exif_gps=True, adid_not_reset=True,
            cross_platform_match=True, location_frequency=3,
            cross_platform_linkability=True, routine_disclosure=True,
            graph_density=2,
        )),
    ]


# ---------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------
def _print_table(title: str, rows: List[Tuple[str, RiskReport]]) -> None:
    print("\n" + title)
    print("=" * len(title))
    header = "%-38s %-22s %7s  %-9s  %5s" % (
        "Profile", "Archetype", "Index", "Tier", "BAI")
    print(header)
    print("-" * len(header))
    for label, report in rows:
        print("%-38s %-22s %7.1f  %-9s  %5.3f" % (
            label,
            report.archetype.value,
            report.risk_index,
            report.risk_tier.value,
            report.bai_score,
        ))


def main() -> None:
    print("OPRCF - OSINT Personal Risk Classification Framework")
    print("Reference demonstration (report Chapter 2)")
    print("NOTE: archetype coefficients are reasoned initial estimates,")
    print("      NOT empirically validated values (Section 2.8).")

    case_rows = [(label, assess(p)) for label, p in case_studies()]
    _print_table("Documented case studies (Section 2.6)", case_rows)

    synth_rows = [(label, assess(p)) for label, p in synthetic_profiles()]
    _print_table("Synthetic exposure spread (Section 2.4)", synth_rows)

    # Full detailed report for the worked example (Section 2.3).
    print("\nDetailed report - worked example (Section 2.3)")
    print("=" * 46)
    worked = next(p for label, p in synthetic_profiles()
                  if label == "Exposed corporate employee")
    print(assess(worked).render())


if __name__ == "__main__":
    main()
