"""OPRCF local web app.

A zero-dependency interactive front end for the OPRCF reference
implementation, built on the Python standard library (http.server). Start it
and open the printed URL in a browser to fill in a profile and receive a full
assessment: Risk Index, tier, per-surface breakdown, triggered flags, and a
prioritised remediation plan with links to authoritative external guidance.

    python serve.py            # serves on http://127.0.0.1:8000
    python serve.py 8080       # custom port
    PORT=8080 python serve.py  # custom port via environment

Optional live breach lookup (Have I Been Pwned) is available when the
HIBP_API_KEY environment variable is set; see integrations.py. Standard
library only - nothing to install.
"""

import html
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from oprcf import Archetype, Profile, Surface, assess
from remediation import TIER_MEANING, build_plan

TIER_COLOURS = {
    "Low": "#1a7f37", "Moderate": "#9a6700",
    "High": "#bc4c00", "Critical": "#cf222e",
}
SEVERITY_CLASS = {"Critical": "sev-critical", "High": "sev-high",
                  "Moderate": "sev-moderate"}

ARCHETYPE_LABELS = [
    ("general_civilian", "1 - General Civilian"),
    ("corporate_employee", "2 - Corporate Employee"),
    ("high_risk_individual", "3 - High-Risk Individual"),
]

CHECKBOXES = [
    ("breach_hit", "Confirmed breach hit",
     "Your email, phone, or address appears in a known data breach (e.g. Have "
     "I Been Pwned). Forces the breach surface to 1.0 and floors the score at "
     "High."),
    ("exif_gps", "EXIF GPS in shared images",
     "Photos you post publicly still carry GPS coordinates in their metadata, "
     "revealing exactly where they were taken. Critical flag."),
    ("doc_author", "Document author name exposed",
     "Files you have shared publicly (PDFs, Office docs) contain your real "
     "name in their author metadata."),
    ("device_model", "Device model visible",
     "Image metadata reveals the phone or camera model you used."),
    ("cross_platform_match", "Username match on 3+ platforms",
     "You reuse the same username across many sites, so an investigator can "
     "link the accounts together (Phase 1 social signal)."),
    ("adid_not_reset", "Advertising Identifier not reset",
     "Your phone's ad ID has never been reset. It acts like a persistent "
     "licence plate tracking you across apps and data-broker datasets."),
    ("default_hostname", "Default personal device hostname",
     "Your device name identifies you (e.g. \"Joseph's iPhone\") and is "
     "broadcast on networks you join."),
    ("wifi_probe", "Wi-Fi probe exposure",
     "Your phone broadcasts the names of networks it has joined before, "
     "leaking places you frequent."),
    ("linkability", "Cross-platform linkability (BAI)",
     "Same name, handle, or profile photo on 3+ platforms. A behavioural "
     "amplifier feeding the BAI - related to, but scored separately from, the "
     "Phase 1 username match above."),
    ("routine_disclosure", "Public routine / schedule disclosure (BAI)",
     "You regularly post your daily schedule, workplace, or predictable "
     "travel, enabling pattern-of-life analysis. Adds 10 points before tier "
     "classification."),
]

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OPRCF - OSINT Personal Risk Classification</title>
<style>
  :root {{ --accent: {accent}; --bg:#f6f8fa; --card:#fff; --line:#d0d7de;
          --ink:#1f2328; --muted:#6e7781; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
         margin:0; background:var(--bg); color:var(--ink); line-height:1.5; }}
  .hero {{ background:linear-gradient(135deg,#0d1117,#1f2937); color:#fff;
          padding:2rem 1rem; }}
  .hero .wrap {{ display:flex; align-items:center; gap:1rem; }}
  .logo {{ font-size:1.7rem; font-weight:800; letter-spacing:-.02em; }}
  .hero p {{ margin:.3rem 0 0; color:#c9d1d9; font-size:.9rem; max-width:60ch; }}
  .pill {{ display:inline-block; margin-top:.6rem; padding:.2rem .6rem;
          border:1px solid #30363d; border-radius:999px; font-size:.72rem;
          color:#c9d1d9; }}
  .wrap {{ max-width:980px; margin:0 auto; padding:0 1rem; }}
  main {{ padding:1.75rem 0 3rem; }}
  h2.sec {{ font-size:.78rem; text-transform:uppercase; letter-spacing:.05em;
           color:var(--muted); margin:0 0 1rem; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:1.25rem; }}
  .card {{ background:var(--card); border:1px solid var(--line);
          border-radius:12px; padding:1.25rem; }}
  label {{ display:block; font-size:.85rem; font-weight:600; margin:.85rem 0 .15rem; }}
  .hint {{ color:var(--muted); font-size:.74rem; line-height:1.35; margin:0 0 .35rem; }}
  select, input[type=number], input[type=email] {{ width:100%; padding:.45rem .55rem;
    border:1px solid var(--line); border-radius:7px; font-size:.9rem;
    background:#fff; color:inherit; }}
  .chk {{ margin:.7rem 0; font-size:.85rem; }}
  .chk-top {{ display:flex; align-items:flex-start; gap:.5rem; font-weight:600; }}
  .chk input {{ margin-top:.2rem; }}
  .chk .hint {{ margin:.12rem 0 0 1.6rem; }}
  button {{ margin-top:1.4rem; width:100%; padding:.75rem; font-size:1rem;
           font-weight:700; color:#fff; background:var(--accent); border:0;
           border-radius:9px; cursor:pointer; }}
  button:hover {{ filter:brightness(.94); }}
  /* result */
  .result {{ background:var(--card); border:1px solid var(--line);
            border-top:6px solid var(--accent); border-radius:12px;
            padding:1.5rem; margin-bottom:1.75rem; }}
  .res-top {{ display:flex; flex-wrap:wrap; align-items:center; gap:1.25rem; }}
  .badge {{ padding:.25rem .7rem; border-radius:999px; background:var(--accent);
           color:#fff; font-weight:800; font-size:.95rem; }}
  .index {{ font-size:2.6rem; font-weight:800; color:var(--accent); line-height:1; }}
  .meta {{ color:var(--muted); font-size:.85rem; }}
  .meaning {{ margin:1rem 0 0; font-size:.92rem; }}
  .gauge {{ margin:1.1rem 0 .3rem; position:relative; }}
  .gauge-track {{ height:14px; border-radius:999px;
    background:linear-gradient(to right,#1a7f37 0 25%,#9a6700 25% 50%,
      #bc4c00 50% 75%,#cf222e 75% 100%); }}
  .gauge-mark {{ position:absolute; top:-5px; width:3px; height:24px;
    background:#0d1117; border-radius:2px; }}
  .gauge-scale {{ display:flex; justify-content:space-between; color:var(--muted);
    font-size:.68rem; margin-top:.2rem; }}
  .bars {{ margin:1.25rem 0 .25rem; }}
  .bar-row {{ display:grid; grid-template-columns:135px 1fr 46px; align-items:center;
    gap:.5rem; margin:.35rem 0; font-size:.8rem; }}
  .track {{ background:#eaeef2; border-radius:999px; height:9px; }}
  .fill {{ background:var(--accent); height:9px; border-radius:999px; }}
  .chips {{ display:flex; flex-wrap:wrap; gap:.4rem; margin-top:.4rem; }}
  .chip {{ background:#eef2f6; color:#444c56; border-radius:999px;
    padding:.18rem .6rem; font-size:.74rem; }}
  /* remediation */
  .rec {{ border:1px solid var(--line); border-radius:11px; padding:1rem 1.1rem;
    margin:.8rem 0; background:#fff; }}
  .rec-head {{ display:flex; align-items:center; gap:.6rem; }}
  .rec-head h3 {{ margin:0; font-size:1rem; }}
  .sev {{ font-size:.66rem; font-weight:800; text-transform:uppercase;
    letter-spacing:.04em; padding:.16rem .5rem; border-radius:999px; color:#fff; }}
  .sev-critical {{ background:#cf222e; }} .sev-high {{ background:#bc4c00; }}
  .sev-moderate {{ background:#9a6700; }}
  .rec .why {{ color:#444c56; font-size:.85rem; margin:.55rem 0; }}
  .rec ol {{ margin:.4rem 0 .6rem; padding-left:1.2rem; font-size:.86rem; }}
  .rec ol li {{ margin:.2rem 0; }}
  .rec .links a {{ display:inline-block; margin:.15rem .5rem .15rem 0;
    font-size:.78rem; color:#0969da; text-decoration:none;
    border:1px solid #d0e3ff; background:#f3f8ff; padding:.18rem .55rem;
    border-radius:7px; }}
  .rec .links a:hover {{ background:#e7f1ff; }}
  .note {{ font-size:.82rem; padding:.6rem .8rem; border-radius:8px; margin:.5rem 0 0; }}
  .note-ok {{ background:#e6f4ea; color:#0f5132; }}
  .note-info {{ background:#eef2f6; color:#444c56; }}
  .note-warn {{ background:#fff4e5; color:#7a4f01; }}
  .muted {{ color:var(--muted); font-size:.75rem; margin-top:1.5rem; }}
  @media (max-width:760px) {{ .grid {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<div class="hero"><div class="wrap">
  <div>
    <div class="logo">OPRCF</div>
    <p>OSINT Personal Risk Classification Framework &mdash; a three-phase
       self-assessment that turns your public exposure into a 0&ndash;100 Risk
       Index with a prioritised, linked remediation plan.</p>
    <span class="pill">Defensive, consented, self-directed use only &middot;
      coefficients are reasoned estimates, not yet empirically validated</span>
  </div>
</div></div>
<main class="wrap">
  {result}
  <form method="post" action="/">
    <div class="card" style="margin-bottom:1.25rem">
      <h2 class="sec">Live breach check &mdash; optional</h2>
      <label>Your email (checked against Have I Been Pwned)</label>
      <p class="hint">First-person use only. Requires your own free HIBP API key
        in the <code>HIBP_API_KEY</code> environment variable. If found, the
        breach signal is set automatically. {hibp_state}</p>
      <input type="email" name="email" placeholder="you@example.com"
             value="{email}">
      <label class="chk-top" style="margin-top:.6rem"><input type="checkbox"
        name="hibp_lookup" value="1"{hibp_checked}>
        <span>Look me up on Have I Been Pwned when I assess</span></label>
    </div>
    <h2 class="sec">Build your profile</h2>
    <div class="grid">
      <div class="card">
        <h2 class="sec">Phase 1 &mdash; Surfaces</h2>
        <label>Archetype</label>
        <p class="hint">Your threat <em>profile</em>, not your risk tolerance.
          Civilian = everyday phishing/credential risk; Corporate Employee =
          targeted for espionage and social engineering; High-Risk = journalist,
          activist, executive, or official facing sophisticated actors. When
          unsure, pick the higher one.</p>
        <select name="archetype">{archetype_options}</select>
        <label>Social media surface (0.0&ndash;1.0)</label>
        <p class="hint">How exposed your public social media is overall: real
          name, geotagged posts, public friend list, check-ins.
          0 = nothing public, 1 = fully exposed.</p>
        <input type="number" name="social_media" min="0" max="1" step="0.1"
               value="{social_media}">
        <label>Public records base (0.0&ndash;1.0)</label>
        <p class="hint">Overall estimate of how much of you sits in public
          records and people-search sites. Use the count below for precision.</p>
        <input type="number" name="public_records" min="0" max="1" step="0.1"
               value="{public_records}">
        <label>Confirmed aggregator listings (+0.2 each)</label>
        <p class="hint">How many data-broker / people-search sites list you
          (Spokeo, Whitepages, etc.). Each listing adds 0.2 to the surface.</p>
        <input type="number" name="aggregator_listings" min="0" step="1"
               value="{aggregator_listings}">
        <label>Mobile footprint base (0.0&ndash;1.0)</label>
        <p class="hint">General estimate of your phone's trackability, on top of
          the specific mobile signals on the right (ad ID, hostname, Wi-Fi).</p>
        <input type="number" name="mobile_footprint" min="0" max="1" step="0.1"
               value="{mobile_footprint}">
      </div>
      <div class="card">
        <h2 class="sec">Signals &amp; behaviour</h2>
        <p class="hint">Tick every signal that is true of you. Each maps to a
          specific, observable exposure in the report's taxonomy.</p>
        {checkboxes}
        <label>Location posting frequency</label>
        <p class="hint">How often you post your real-time location. Heavier
          posting is the strongest behavioural amplifier.</p>
        <select name="location_frequency">{location_options}</select>
        <label>Graph density</label>
        <p class="hint">How visible your social network is &mdash; private,
          partly visible, or every connection public.</p>
        <select name="graph_density">{graph_options}</select>
      </div>
    </div>
    <button type="submit">Assess my exposure</button>
  </form>
  <p class="muted">Runs locally on the Python standard library. Consumes only
    already-public signals; introduces no new collection (report Section 2.9).
    Every score is paired with concrete remediation.</p>
</main>
</body>
</html>"""


def _select_options(pairs, selected):
    out = []
    for value, label in pairs:
        sel = " selected" if str(value) == str(selected) else ""
        out.append('<option value="%s"%s>%s</option>'
                   % (html.escape(str(value)), sel, html.escape(label)))
    return "".join(out)


def _checkboxes(values):
    out = []
    for field, label, hint in CHECKBOXES:
        checked = " checked" if values.get(field) else ""
        out.append(
            '<div class="chk"><label class="chk-top">'
            '<input type="checkbox" name="%s" value="1"%s>'
            '<span>%s</span></label><p class="hint">%s</p></div>'
            % (field, checked, html.escape(label), html.escape(hint)))
    return "".join(out)


def _profile_from_form(form):
    def num(name, default=0.0):
        try:
            return float(form.get(name, [default])[0])
        except (TypeError, ValueError):
            return default

    def integer(name, default=0):
        try:
            return int(form.get(name, [default])[0])
        except (TypeError, ValueError):
            return default

    return Profile(
        archetype=Archetype(form.get("archetype", ["general_civilian"])[0]),
        social_media=num("social_media"),
        public_records=num("public_records"),
        aggregator_listings=integer("aggregator_listings"),
        mobile_footprint=num("mobile_footprint"),
        breach_hit="breach_hit" in form,
        exif_gps="exif_gps" in form,
        doc_author="doc_author" in form,
        device_model="device_model" in form,
        cross_platform_match="cross_platform_match" in form,
        adid_not_reset="adid_not_reset" in form,
        default_hostname="default_hostname" in form,
        wifi_probe="wifi_probe" in form,
        location_frequency=integer("location_frequency"),
        cross_platform_linkability="linkability" in form,
        routine_disclosure="routine_disclosure" in form,
        graph_density=integer("graph_density"),
    )


def _gauge(index):
    pos = max(0.0, min(100.0, index))
    return (
        '<div class="gauge"><div class="gauge-track"></div>'
        '<div class="gauge-mark" style="left:%.1f%%"></div></div>'
        '<div class="gauge-scale"><span>0 Low</span><span>25 Mod</span>'
        '<span>50 High</span><span>75 Critical</span><span>100</span></div>'
        % pos)


def _remediation_html(plan):
    if not plan:
        return ('<div class="note note-ok">No active exposure signals - nothing '
                'to remediate. Keep up good hygiene and re-check periodically.</div>')
    cards = []
    for g in plan:
        steps = "".join("<li>%s</li>" % html.escape(s) for s in g.steps)
        links = "".join(
            '<a href="%s" target="_blank" rel="noopener noreferrer">%s &#8599;</a>'
            % (html.escape(url), html.escape(label)) for label, url in g.links)
        cards.append(
            '<div class="rec"><div class="rec-head">'
            '<span class="sev %s">%s</span><h3>%s</h3></div>'
            '<p class="why">%s</p><ol>%s</ol><div class="links">%s</div></div>'
            % (SEVERITY_CLASS.get(g.severity, "sev-moderate"),
               html.escape(g.severity), html.escape(g.title),
               html.escape(g.why), steps, links))
    return "".join(cards)


def _result_html(profile, report, lookup_note=""):
    accent = TIER_COLOURS.get(report.risk_tier.value, "#1f6feb")
    bars = []
    for surface in Surface:
        score = report.adjusted_scores[surface]
        bars.append(
            '<div class="bar-row"><span>%s</span>'
            '<span class="track"><span class="fill" style="width:%d%%;'
            'background:%s"></span></span><span>%.3f</span></div>'
            % (surface.value, int(round(score * 100)), accent, score))
    flags = "".join('<span class="chip">%s</span>' % html.escape(f)
                    for f in report.triggered_flags) or \
        '<span class="chip">none</span>'
    plan = build_plan(profile, report)
    meaning = TIER_MEANING.get(report.risk_tier, "")
    return (
        '<div class="result">'
        '%s'
        '<div class="res-top"><span class="badge">%s</span>'
        '<span class="index">%.1f</span>'
        '<span class="meta">/ 100&nbsp;&nbsp;&bull;&nbsp;&nbsp;BAI %.3f&nbsp;&nbsp;'
        '&bull;&nbsp;&nbsp;archetype: %s</span></div>'
        '%s'
        '<p class="meaning">%s</p>'
        '<div class="bars"><h2 class="sec">Archetype-adjusted surfaces</h2>%s</div>'
        '<h2 class="sec">Triggered flags</h2><div class="chips">%s</div>'
        '<h2 class="sec" style="margin-top:1.4rem">Prioritised remediation plan'
        '</h2>%s'
        '</div>'
        % (lookup_note, report.risk_tier.value, report.risk_index,
           report.bai_score, html.escape(report.archetype.value),
           _gauge(report.risk_index), html.escape(meaning),
           "".join(bars), flags, _remediation_html(plan)))


def _hibp_state():
    return ("A key is configured." if os.environ.get("HIBP_API_KEY")
            else "No key is set, so live lookup is disabled - tick the breach "
                 "box manually if you know you're breached.")


def _render(form=None, report=None, error=None, lookup_note=""):
    form = form or {}
    accent = TIER_COLOURS.get(report.risk_tier.value, "#1f6feb") if report \
        else "#1f6feb"
    if error:
        result = ('<div class="result"><strong style="color:#cf222e">'
                  'Invalid input:</strong> %s</div>' % html.escape(error))
    elif report:
        result = _result_html(form.get("_profile"), report, lookup_note)
    else:
        result = ""

    def first(name, default):
        val = form.get(name, [default])
        return html.escape(str(val[0] if isinstance(val, list) else val))

    return PAGE.format(
        accent=accent, result=result,
        hibp_state=html.escape(_hibp_state()),
        email=first("email", ""),
        hibp_checked=" checked" if form.get("hibp_lookup") else "",
        archetype_options=_select_options(
            ARCHETYPE_LABELS, form.get("archetype", ["general_civilian"])[0]),
        social_media=first("social_media", "0.0"),
        public_records=first("public_records", "0.0"),
        aggregator_listings=first("aggregator_listings", "0"),
        mobile_footprint=first("mobile_footprint", "0.0"),
        checkboxes=_checkboxes(form),
        location_options=_select_options(
            [(0, "0 - never"), (1, "1 - weekly"), (2, "2 - daily"),
             (3, "3 - real-time check-ins")],
            form.get("location_frequency", ["0"])[0]),
        graph_options=_select_options(
            [(0, "0 - private"), (1, "1 - semi-public"),
             (2, "2 - fully public")],
            form.get("graph_density", ["0"])[0]),
    )


def _maybe_breach_lookup(form):
    """Optionally query HIBP for the supplied email; returns an HTML note."""
    if not form.get("hibp_lookup"):
        return ""
    email = (form.get("email", [""])[0] or "").strip()
    if not email:
        return '<div class="note note-warn">Tick-box set but no email supplied.</div>'
    try:
        import integrations
        hit, names = integrations.breach_signal_for_email(email)
    except Exception as exc:  # integrations raises IntegrationError; be defensive
        return ('<div class="note note-info">Live breach lookup unavailable: %s'
                '</div>' % html.escape(str(exc)))
    if hit:
        form["breach_hit"] = ["1"]
        return ('<div class="note note-warn">Have I Been Pwned: this email is in '
                '%d breach(es) &mdash; %s. Breach signal set automatically.</div>'
                % (len(names), html.escape(", ".join(names[:8]))))
    return ('<div class="note note-ok">Have I Been Pwned: no breaches found for '
            'that email.</div>')


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, status=200):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self._send("<h1>404</h1>", status=404)
            return
        self._send(_render())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        form = parse_qs(raw, keep_blank_values=True)
        try:
            note = _maybe_breach_lookup(form)   # may set form['breach_hit']
            profile = _profile_from_form(form)
            report = assess(profile)
            form["_profile"] = profile
            self._send(_render(form=form, report=report, lookup_note=note))
        except (ValueError, TypeError, KeyError) as exc:
            self._send(_render(form=form, error=str(exc)))

    def log_message(self, *args):
        pass


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    port = int(argv[0]) if argv else int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = "http://127.0.0.1:%d" % port
    print("OPRCF web app running at %s  (Ctrl+C to stop)" % url)
    if not os.environ.get("HIBP_API_KEY"):
        print("  (set HIBP_API_KEY to enable the optional live breach lookup)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()
