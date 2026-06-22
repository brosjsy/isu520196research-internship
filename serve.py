"""OPRCF local web app.

A zero-dependency interactive front end for the OPRCF reference
implementation, built on the Python standard library (http.server). Start it
and open the printed URL in a browser to fill in a profile and see the
assessment, per-surface breakdown, triggered flags, and ranked remediation.

    python serve.py            # serves on http://127.0.0.1:8000
    python serve.py 8080       # custom port
    PORT=8080 python serve.py  # custom port via environment

Standard library only - nothing to install.
"""

import html
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from oprcf import Archetype, Profile, Surface, assess

# Tier -> accent colour for the result badge.
TIER_COLOURS = {
    "Low": "#1a7f37",
    "Moderate": "#9a6700",
    "High": "#bc4c00",
    "Critical": "#cf222e",
}

ARCHETYPE_LABELS = [
    ("general_civilian", "1 - General Civilian"),
    ("corporate_employee", "2 - Corporate Employee"),
    ("high_risk_individual", "3 - High-Risk Individual"),
]

# (form field, label, plain-language hint) for the boolean toggles.
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
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; padding: 2rem 1rem; background: #f6f8fa; color: #1f2328; }}
  .wrap {{ max-width: 880px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
  .sub {{ color: #57606a; margin: 0 0 1.5rem; font-size: .9rem; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
  .card {{ background: #fff; border: 1px solid #d0d7de; border-radius: 10px;
          padding: 1.25rem; }}
  .card h2 {{ font-size: .8rem; text-transform: uppercase; letter-spacing: .04em;
             color: #57606a; margin: 0 0 1rem; }}
  label {{ display: block; font-size: .85rem; font-weight: 600;
          margin: .85rem 0 .15rem; }}
  .hint {{ color: #6e7781; font-size: .74rem; line-height: 1.35;
          margin: 0 0 .35rem; }}
  select, input[type=number] {{ width: 100%; padding: .4rem .5rem;
    border: 1px solid #d0d7de; border-radius: 6px; font-size: .9rem;
    background: #fff; color: inherit; }}
  .chk {{ margin: .7rem 0; font-size: .85rem; }}
  .chk-top {{ display: flex; align-items: flex-start; gap: .5rem;
             font-weight: 600; }}
  .chk input {{ margin-top: .2rem; }}
  .chk .hint {{ margin: .12rem 0 0 1.6rem; }}
  button {{ margin-top: 1.5rem; width: 100%; padding: .7rem; font-size: 1rem;
           font-weight: 600; color: #fff; background: #1f6feb; border: 0;
           border-radius: 8px; cursor: pointer; }}
  button:hover {{ background: #1a5fd0; }}
  .result {{ margin-bottom: 1.5rem; border-left: 6px solid {accent};
            background: #fff; border-radius: 10px; padding: 1.25rem;
            border: 1px solid #d0d7de; }}
  .badge {{ display: inline-block; padding: .2rem .6rem; border-radius: 999px;
           background: {accent}; color: #fff; font-weight: 700;
           font-size: .85rem; }}
  .index {{ font-size: 2.4rem; font-weight: 800; color: {accent};
           line-height: 1; }}
  .bars {{ margin: 1rem 0; }}
  .bar-row {{ display: grid; grid-template-columns: 130px 1fr 48px;
             align-items: center; gap: .5rem; margin: .35rem 0;
             font-size: .8rem; }}
  .track {{ background: #eaeef2; border-radius: 999px; height: 10px; }}
  .fill {{ background: {accent}; height: 10px; border-radius: 999px; }}
  ul {{ margin: .4rem 0 0; padding-left: 1.2rem; font-size: .85rem; }}
  .flags li {{ color: #57606a; }}
  .muted {{ color: #8c959f; font-size: .75rem; margin-top: 1.5rem; }}
  @media (max-width: 720px) {{ .grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="wrap">
  <h1>OPRCF &mdash; OSINT Personal Risk Classification</h1>
  <p class="sub">Three-phase reference implementation (report Chapter 2).
     Coefficients are reasoned initial estimates, not empirically validated
     (Section 2.8).</p>
  {result}
  <form method="post" action="/">
    <div class="grid">
      <div class="card">
        <h2>Phase 1 &mdash; Surfaces</h2>
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
        <h2>Signals &amp; behaviour</h2>
        <p class="hint">Tick every signal that is true of you. Each maps to a
          specific, observable exposure described in the report's taxonomy.</p>
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
    <button type="submit">Assess exposure</button>
  </form>
  <p class="muted">Defensive, consented, self-directed use only (Section 2.9).
     Running locally on the Python standard library.</p>
</div>
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

    def flag(name):
        return name in form

    return Profile(
        archetype=Archetype(form.get("archetype", ["general_civilian"])[0]),
        social_media=num("social_media"),
        public_records=num("public_records"),
        aggregator_listings=integer("aggregator_listings"),
        mobile_footprint=num("mobile_footprint"),
        breach_hit=flag("breach_hit"),
        exif_gps=flag("exif_gps"),
        doc_author=flag("doc_author"),
        device_model=flag("device_model"),
        cross_platform_match=flag("cross_platform_match"),
        adid_not_reset=flag("adid_not_reset"),
        default_hostname=flag("default_hostname"),
        wifi_probe=flag("wifi_probe"),
        location_frequency=integer("location_frequency"),
        cross_platform_linkability=flag("linkability"),
        routine_disclosure=flag("routine_disclosure"),
        graph_density=integer("graph_density"),
    )


def _result_html(report):
    rows = []
    for surface in Surface:
        score = report.adjusted_scores[surface]
        rows.append(
            '<div class="bar-row"><span>%s</span>'
            '<span class="track"><span class="fill" style="width:%d%%"></span></span>'
            '<span>%.3f</span></div>'
            % (surface.value, int(round(score * 100)), score))
    flags = "".join("<li>%s</li>" % html.escape(f)
                    for f in report.triggered_flags) or "<li>none</li>"
    remediation = "".join("<li>%s</li>" % html.escape(a)
                          for a in report.remediation) or "<li>none</li>"
    return (
        '<div class="result">'
        '<div><span class="badge">%s</span></div>'
        '<p style="margin:.6rem 0 0"><span class="index">%.1f</span>'
        ' <span style="color:#57606a">/ 100 &nbsp;&bull;&nbsp; BAI %.3f</span></p>'
        '<div class="bars"><h2 style="font-size:.75rem;text-transform:uppercase;'
        'letter-spacing:.04em;color:#57606a;margin:.5rem 0">'
        'Archetype-adjusted surfaces</h2>%s</div>'
        '<h2 style="font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;'
        'color:#57606a;margin:.5rem 0 0">Triggered flags</h2>'
        '<ul class="flags">%s</ul>'
        '<h2 style="font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;'
        'color:#57606a;margin:.7rem 0 0">Top remediation</h2><ul>%s</ul>'
        '</div>'
        % (report.risk_tier.value, report.risk_index, report.bai_score,
           "".join(rows), flags, remediation))


def _render(form=None, report=None, error=None):
    form = form or {}
    accent = TIER_COLOURS.get(report.risk_tier.value, "#1f6feb") if report \
        else "#1f6feb"
    if error:
        result = ('<div class="result"><strong style="color:#cf222e">'
                  'Invalid input:</strong> %s</div>' % html.escape(error))
    elif report:
        result = _result_html(report)
    else:
        result = ""

    def first(name, default):
        val = form.get(name, [default])
        return html.escape(str(val[0] if isinstance(val, list) else val))

    return PAGE.format(
        accent=accent,
        result=result,
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
            report = assess(_profile_from_form(form))
            self._send(_render(form=form, report=report))
        except (ValueError, TypeError, KeyError) as exc:
            self._send(_render(form=form, error=str(exc)))

    def log_message(self, *args):
        pass  # keep the console quiet


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    port = int(argv[0]) if argv else int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = "http://127.0.0.1:%d" % port
    print("OPRCF web app running at %s  (Ctrl+C to stop)" % url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()
