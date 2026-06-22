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

# (form field, label, checked?) for the boolean toggles.
CHECKBOXES = [
    ("breach_hit", "Confirmed breach hit (surface 1.0 + floor)"),
    ("exif_gps", "EXIF GPS present in shared images (critical)"),
    ("doc_author", "Document author name exposed (0.5)"),
    ("device_model", "Device model visible in metadata (0.2)"),
    ("cross_platform_match", "Username match on 3+ platforms"),
    ("adid_not_reset", "Advertising Identifier not reset (1.0)"),
    ("default_hostname", "Default personal device hostname (0.7)"),
    ("wifi_probe", "Wi-Fi probe exposure confirmed (0.5)"),
    ("linkability", "Cross-platform linkability (BAI)"),
    ("routine_disclosure", "Public routine / schedule disclosure (BAI)"),
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
  label {{ display: block; font-size: .85rem; margin: .65rem 0 .2rem; }}
  select, input[type=number] {{ width: 100%; padding: .4rem .5rem;
    border: 1px solid #d0d7de; border-radius: 6px; font-size: .9rem;
    background: #fff; color: inherit; }}
  .chk {{ display: flex; align-items: flex-start; gap: .5rem; margin: .55rem 0;
         font-size: .85rem; }}
  .chk input {{ margin-top: .15rem; }}
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
        <select name="archetype">{archetype_options}</select>
        <label>Social media surface (0.0&ndash;1.0)</label>
        <input type="number" name="social_media" min="0" max="1" step="0.1"
               value="{social_media}">
        <label>Public records base (0.0&ndash;1.0)</label>
        <input type="number" name="public_records" min="0" max="1" step="0.1"
               value="{public_records}">
        <label>Confirmed aggregator listings (+0.2 each)</label>
        <input type="number" name="aggregator_listings" min="0" step="1"
               value="{aggregator_listings}">
        <label>Mobile footprint base (0.0&ndash;1.0)</label>
        <input type="number" name="mobile_footprint" min="0" max="1" step="0.1"
               value="{mobile_footprint}">
      </div>
      <div class="card">
        <h2>Signals &amp; behaviour</h2>
        {checkboxes}
        <label>Location posting frequency</label>
        <select name="location_frequency">{location_options}</select>
        <label>Graph density</label>
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
    for field, label in CHECKBOXES:
        checked = " checked" if values.get(field) else ""
        out.append(
            '<label class="chk"><input type="checkbox" name="%s" value="1"%s>'
            '<span>%s</span></label>' % (field, checked, html.escape(label)))
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
