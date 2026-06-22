"""OPRCF remediation knowledge base.

Maps the observable signals in a Profile to concrete, prioritised remediation
guidance: why the exposure matters, step-by-step actions, and links to
authoritative external guidance (EFF Surveillance Self-Defense, Have I Been
Pwned, ExifTool, data-broker opt-out resources, and official platform docs).

This is the presentation/advice layer; it imports the framework but adds no
scoring logic. The report's design (Section 2.9) pairs every score with
concrete remediation, which is what this module supplies.

Note on links: these point to authoritative organisations and official
support pages that are the canonical starting points for each fix. Vendor
help-centre URLs occasionally move; if one 404s, search the linked domain for
the titled article.
"""

from dataclasses import dataclass, field
from typing import List, Tuple

from oprcf import Profile, RiskReport, RiskTier, Surface


@dataclass
class Guidance:
    """A single prioritised remediation item."""
    topic: str
    title: str
    severity: str                      # "Critical" | "High" | "Moderate"
    why: str
    steps: List[str] = field(default_factory=list)
    links: List[Tuple[str, str]] = field(default_factory=list)  # (label, url)


# Plain-language meaning of each tier, shown above the remediation plan.
TIER_MEANING = {
    RiskTier.LOW: (
        "Your public exposure is minimal. Keep up good hygiene and re-check "
        "periodically  -  exposure tends to creep up over time."),
    RiskTier.MODERATE: (
        "You have a noticeable but manageable footprint. Work through the "
        "items below to reduce how easily your signals can be linked together."),
    RiskTier.HIGH: (
        "Your exposure is significant and likely correlatable across multiple "
        "surfaces. Prioritise the critical items below and act on them now."),
    RiskTier.CRITICAL: (
        "Your exposure is severe: multiple high-value signals are public and "
        "linkable. Treat every item below as urgent, starting from the top."),
}

# Canonical external resources reused across topics.
SSD_HOME = ("EFF Surveillance Self-Defense", "https://ssd.eff.org/")
HIBP = ("Have I Been Pwned", "https://haveibeenpwned.com/")
EXIFTOOL = ("ExifTool (strip metadata)", "https://exiftool.org/")
EFF_ADID = ("EFF: How to disable Ad ID tracking (iOS & Android)",
            "https://www.eff.org/deeplinks/2022/05/how-disable-ad-id-"
            "tracking-ios-and-android-and-why-you-should-do-it-now")
DATA_BROKER_LIST = ("Big Ass Data-Broker Opt-Out List",
                    "https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List")
PRIVACY_RIGHTS = ("Privacy Rights Clearinghouse: data brokers",
                  "https://privacyrights.org/data-brokers")
SSD_SOCIAL = ("EFF SSD: Protecting yourself on social networks",
              "https://ssd.eff.org/module/how-protect-yourself-social-networks")
SSD_PASSWORDS = ("EFF SSD: Creating strong passwords",
                 "https://ssd.eff.org/module/creating-strong-passwords")
SSD_2FA = ("EFF SSD: Enabling two-factor authentication",
           "https://ssd.eff.org/module/how-enable-two-factor-authentication")
APPLE_ATT = ("Apple: control app tracking (ATT)",
             "https://support.apple.com/en-us/HT212025")
APPLE_WIFI = ("Apple: use private Wi-Fi addresses",
              "https://support.apple.com/en-us/HT211227")
ANDROID_PRIVACY = ("Google: Android privacy & ads settings",
                   "https://support.google.com/android/answer/3405269")


# Each topic's static guidance. The builder selects and orders these per profile.
_GUIDANCE = {
    "breach": Guidance(
        topic="breach", title="Contain the confirmed credential breach",
        severity="Critical",
        why="Your email, phone, or address is in a known breach corpus. This is "
            "the primary identity-anchor vector: attackers use it for "
            "credential stuffing, targeted phishing, and account takeover.",
        steps=[
            "Look up exactly which breaches you appear in on Have I Been Pwned.",
            "Change the password on every affected account, and on any other "
            "account that reused the same password.",
            "Switch to a password manager so every account has a unique password.",
            "Turn on two-factor authentication (prefer an authenticator app or "
            "hardware key over SMS) on email, banking, and social accounts.",
            "Treat any email referencing the breached service as suspicious.",
        ],
        links=[HIBP, SSD_PASSWORDS, SSD_2FA]),

    "exif_gps": Guidance(
        topic="exif_gps", title="Strip EXIF GPS from shared photos",
        severity="Critical",
        why="Photos you publish still carry the exact GPS coordinates where they "
            "were taken. This is the vector that located John McAfee in 2012  -  "
            "analysts read the coordinates straight out of the image file.",
        steps=[
            "Turn off camera location permission so new photos embed no GPS.",
            "Strip metadata from any image before sharing (ExifTool, or your "
            "phone's built-in 'remove location' share option).",
            "Re-check images already posted publicly and replace or remove them.",
            "Prefer platforms that strip metadata on upload  -  but verify, don't "
            "assume.",
        ],
        links=[EXIFTOOL, SSD_HOME]),

    "adid": Guidance(
        topic="adid", title="Reset and limit your Advertising Identifier",
        severity="Critical",
        why="A persistent advertising ID acts like a licence plate that follows "
            "you across apps and data-broker datasets. This is the vector behind "
            "the 2021 advertising-ID de-anonymisation of a senior official from "
            "24 months of commercial location data.",
        steps=[
            "Reset your Advertising Identifier now (iOS: turn off 'Allow Apps to "
            "Request to Track'; Android: delete/reset the advertising ID).",
            "Deny location permission to any app that doesn't need it; set the "
            "rest to 'While Using' rather than 'Always'.",
            "Disable 'Share analytics'/aggregated-data sharing in fitness and "
            "social apps.",
            "Audit installed apps and remove ones you no longer use.",
        ],
        links=[EFF_ADID, APPLE_ATT, ANDROID_PRIVACY]),

    "public_records": Guidance(
        topic="public_records", title="Opt out of data brokers & people-search",
        severity="High",
        why="Data brokers and people-search sites aggregate your address, phone, "
            "relatives, and history into a single profile that powers precision "
            "social engineering and doxxing.",
        steps=[
            "Search the major people-search sites (Spokeo, Whitepages, "
            "BeenVerified, etc.) for your name and note every listing.",
            "Submit opt-out / removal requests for each  -  community lists give "
            "direct opt-out URLs for hundreds of brokers.",
            "Consider a paid removal service if the volume is large, but verify "
            "what it covers.",
            "Re-check quarterly: brokers frequently re-list after removal.",
        ],
        links=[DATA_BROKER_LIST, PRIVACY_RIGHTS]),

    "social_media": Guidance(
        topic="social_media", title="Lock down social-media exposure",
        severity="High",
        why="A public real name, friend list, geotags, and check-ins give an "
            "investigator a free map of your identity, relationships, and "
            "movements.",
        steps=[
            "Set profiles to private and review who can see posts, friends, and "
            "tags.",
            "Turn off geotagging on posts and remove location history.",
            "Hide or trim your public friend/follower list.",
            "Remove or restrict old posts that reveal home, workplace, or "
            "routine.",
        ],
        links=[SSD_SOCIAL, SSD_HOME]),

    "file_other": Guidance(
        topic="file_other", title="Scrub document & image metadata",
        severity="Moderate",
        why="Files you share carry hidden metadata  -  author name, device model, "
            "software, timestamps  -  that links documents back to you and your "
            "equipment.",
        steps=[
            "Remove metadata before sharing documents (Office: 'Inspect "
            "Document' -> remove personal data; PDFs: sanitise/redact).",
            "Strip image metadata with ExifTool or a trusted stripping tool.",
            "Use a generic author name in your document software settings.",
        ],
        links=[EXIFTOOL, SSD_HOME]),

    "device_network": Guidance(
        topic="device_network", title="Harden device & network fingerprint",
        severity="Moderate",
        why="A default personal hostname (e.g. 'Jane's iPhone') and Wi-Fi probe "
            "requests broadcast who you are and where you've been to anyone "
            "monitoring nearby networks.",
        steps=[
            "Rename your device to something non-identifying.",
            "Enable private/randomised Wi-Fi (MAC) addresses.",
            "Make your phone 'forget' networks you no longer use so it stops "
            "probing for them.",
            "Disable auto-join for open networks.",
        ],
        links=[APPLE_WIFI, ANDROID_PRIVACY]),

    "location_freq": Guidance(
        topic="location_freq", title="Cut real-time location posting",
        severity="High",
        why="Frequent real-time location posts are the single strongest "
            "behavioural amplifier. Individually harmless posts aggregate into a "
            "precise pattern  -  the dynamic that exposed sensitive sites in the "
            "2018 Strava heatmap.",
        steps=[
            "Stop posting live location/check-ins; share location after you've "
            "left, if at all.",
            "Disable real-time location sharing in fitness and social apps.",
            "Make existing activity/location history private or delete it.",
        ],
        links=[SSD_HOME, EFF_ADID]),

    "routine": Guidance(
        topic="routine", title="Break up your public pattern-of-life",
        severity="High",
        why="Regularly publishing your schedule, workplace, and predictable "
            "travel lets an observer anticipate where you'll be  -  a direct "
            "physical-safety and stalking risk.",
        steps=[
            "Stop posting recurring schedules, commutes, and standing plans.",
            "Avoid 'I'm always at X every Tuesday'-style disclosures.",
            "Vary what you share and delay posts that reveal current location.",
        ],
        links=[SSD_HOME, SSD_SOCIAL]),

    "cross_platform": Guidance(
        topic="cross_platform", title="Reduce cross-platform linkability",
        severity="Moderate",
        why="The same username, handle, or profile photo across many platforms "
            "lets anyone enumerate all your accounts from one of them.",
        steps=[
            "Use different usernames/handles on accounts you want kept separate.",
            "Avoid reusing the same profile photo across platforms.",
            "Separate professional and personal identities.",
        ],
        links=[SSD_HOME]),

    "graph": Guidance(
        topic="graph", title="Tighten social-graph visibility",
        severity="Moderate",
        why="A fully public connection graph exposes your network and makes you "
            "a stepping-stone to target the people around you.",
        steps=[
            "Hide your friends/followers/connections list.",
            "Limit who can see your network and tag you.",
            "Review third-party apps with access to your social graph and revoke "
            "unused ones.",
        ],
        links=[SSD_SOCIAL]),
}


def build_plan(profile: Profile, report: RiskReport) -> List[Guidance]:
    """Return ordered, de-duplicated remediation guidance for a profile.

    Topics are selected from the active signals and ordered by priority
    (criticals first, then high-contribution surfaces, then behaviour).
    """
    selected: List[str] = []

    if profile.breach_hit:
        selected.append("breach")
    if profile.exif_gps:
        selected.append("exif_gps")
    if profile.adid_not_reset:
        selected.append("adid")
    if report.surface_scores[Surface.PUBLIC_RECORDS] > 0:
        selected.append("public_records")
    if report.surface_scores[Surface.SOCIAL_MEDIA] > 0:
        selected.append("social_media")
    if (profile.doc_author or profile.device_model) and not profile.exif_gps:
        selected.append("file_other")
    if profile.wifi_probe or profile.default_hostname:
        selected.append("device_network")
    if profile.location_frequency >= 2:
        selected.append("location_freq")
    if profile.routine_disclosure:
        selected.append("routine")
    if profile.cross_platform_match or profile.cross_platform_linkability:
        selected.append("cross_platform")
    if profile.graph_density >= 1:
        selected.append("graph")

    # Priority order for display.
    order = ["breach", "exif_gps", "adid", "location_freq", "routine",
             "public_records", "social_media", "cross_platform",
             "device_network", "file_other", "graph"]
    seen = set()
    plan = []
    for topic in order:
        if topic in selected and topic not in seen:
            seen.add(topic)
            plan.append(_GUIDANCE[topic])
    return plan
