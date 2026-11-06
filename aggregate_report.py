#!/usr/bin/env python3
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_json(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, Exception):
        return None


def parse_gitleaks(data):
    if not data:
        return []
    findings = []
    for item in data:
        findings.append({
            "tool": "gitleaks",
            "severity": item.get("Severity", "MEDIUM").upper(),
            "file": item.get("File", ""),
            "line": str(item.get("StartLine", "")),
            "message": item.get("Description", item.get("RuleID", "")),
        })
    return findings


def parse_hadolint(data):
    if not data:
        return []
    findings = []
    for item in data:
        findings.append({
            "tool": "hadolint",
            "severity": item.get("level", "info").upper(),
            "file": item.get("file", ""),
            "line": str(item.get("line", "")),
            "message": f"{item.get('code', '')}: {item.get('message', '')}",
        })
    return findings


def parse_semgrep(data):
    if not data:
        return []
    findings = []
    for result in data.get("results", []):
        findings.append({
            "tool": "semgrep",
            "severity": result.get("extra", {}).get("severity", "WARNING").upper(),
            "file": result.get("path", ""),
            "line": str(result.get("start", {}).get("line", "")),
            "message": result.get("extra", {}).get("message", ""),
        })
    return findings


def parse_bandit(data):
    if not data:
        return []
    findings = []
    for result in data.get("results", []):
        findings.append({
            "tool": "bandit",
            "severity": result.get("issue_severity", "MEDIUM").upper(),
            "file": result.get("filename", ""),
            "line": str(result.get("line_number", "")),
            "message": f"{result.get('test_id', '')}: {result.get('issue_text', '')}",
        })
    return findings


def parse_safety(data):
    if not data:
        return []
    findings = []
    for item in data:
        if isinstance(item, list):
            findings.append({
                "tool": "safety",
                "severity": "HIGH",
                "file": item[3] if len(item) > 3 else "",
                "line": "",
                "message": f"{item[0]}: {item[1]}",
            })
        elif isinstance(item, dict):
            findings.append({
                "tool": "safety",
                "severity": item.get("severity", "HIGH").upper(),
                "file": item.get("package_name", ""),
                "line": "",
                "message": f"{item.get('vulnerability_id', '')}: {item.get('advisory', '')}",
            })
    return findings


def parse_trivy(data):
    if not data:
        return []
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            findings.append({
                "tool": "trivy",
                "severity": vuln.get("Severity", "UNKNOWN").upper(),
                "file": target,
                "line": "",
                "message": f"{vuln.get('VulnerabilityID', '')}: {vuln.get('Title', vuln.get('PkgName', ''))}",
            })
    return findings


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "WARNING": 4, "INFO": 5, "UNKNOWN": 6}
THRESHOLDS = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generate_html_report(summary, output_path):
    findings = summary.get("findings", [])
    severity_counts = summary.get("severity_counts", {})
    tool_counts = summary.get("tool_counts", {})
    total = len(findings)

    data_json = json.dumps(findings, ensure_ascii=False).replace("</script>", "<\\/script>")

    counts_json = json.dumps({
        "severity": severity_counts,
        "tools": {k: v["total"] for k, v in tool_counts.items()},
        "total": total,
    })

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; color: #1a1a2e; padding: 20px; }}
#app {{ max-width: 1100px; margin: 0 auto; }}
header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }}
header h1 {{ font-size: 1.5rem; font-weight: 600; color: #16213e; }}
#total-count {{ font-size: 0.9rem; color: #6c757d; background: #e9ecef; padding: 2px 10px; border-radius: 12px; }}
.controls {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }}
.controls label {{ font-size: 0.8rem; font-weight: 500; color: #495057; }}
.controls select, .controls input {{
  padding: 5px 10px; border: 1px solid #ced4da; border-radius: 6px; font-size: 0.85rem;
  background: #fff; outline: none;
}}
.controls select:focus, .controls input:focus {{ border-color: #4a6cf7; }}
#search {{ flex: 1; min-width: 180px; }}
.btn {{
  padding: 5px 12px; border: 1px solid #ced4da; border-radius: 6px; font-size: 0.8rem;
  cursor: pointer; background: #fff; color: #495057; white-space: nowrap;
}}
.btn:hover {{ background: #e9ecef; }}
.btn:active {{ background: #dee2e6; }}
#sort-dir {{ font-size: 1rem; padding: 5px 8px; min-width: 36px; text-align: center; }}
#results {{ background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow: hidden; }}
.group {{ border-bottom: 1px solid #e9ecef; }}
.group:last-child {{ border-bottom: none; }}
.group-header {{
  display: flex; align-items: center; gap: 10px; padding: 10px 16px;
  cursor: pointer; user-select: none; transition: background 0.15s;
}}
.group-header:hover {{ background: #f8f9fa; }}
.group-header.collapsed {{ background: #fff; }}
.chevron {{ font-size: 0.7rem; color: #6c757d; width: 14px; text-align: center; transition: transform 0.15s; }}
.chevron.open {{ transform: rotate(90deg); }}
.group-title {{ font-weight: 600; font-size: 0.9rem; color: #16213e; }}
.group-count {{
  margin-left: auto; font-size: 0.75rem; font-weight: 500; padding: 1px 8px;
  border-radius: 10px; background: #e9ecef; color: #495057;
}}
.group-items {{ list-style: none; }}
.group-items.collapsed {{ display: none; }}
.finding {{
  display: flex; align-items: flex-start; gap: 10px; padding: 6px 16px 6px 40px;
  border-top: 1px solid #f1f3f5; font-size: 0.82rem; line-height: 1.5;
}}
.finding:hover {{ background: #fafbfc; }}
.severity-badge {{
  flex-shrink: 0; font-size: 0.65rem; font-weight: 600; padding: 1px 6px;
  border-radius: 4px; letter-spacing: 0.3px; min-width: 52px; text-align: center;
}}
.severity-CRITICAL {{ background: #fff5f5; color: #c92a2a; border: 1px solid #ffc9c9; }}
.severity-HIGH {{ background: #fff4e6; color: #d9480f; border: 1px solid #ffd8a8; }}
.severity-MEDIUM {{ background: #fff9db; color: #9c6b00; border: 1px solid #ffec99; }}
.severity-LOW {{ background: #e3fafc; color: #0b7285; border: 1px solid #99e9f2; }}
.severity-WARNING {{ background: #f8f9fa; color: #495057; border: 1px solid #dee2e6; }}
.severity-INFO {{ background: #f8f9fa; color: #6c757d; border: 1px solid #dee2e6; }}
.severity-UNKNOWN {{ background: #f8f9fa; color: #6c757d; border: 1px solid #dee2e6; }}
.finding-message {{ flex: 1; min-width: 0; }}
.finding-location {{ flex-shrink: 0; color: #868e96; font-size: 0.75rem; }}
.finding-tool {{ flex-shrink: 0; color: #868e96; font-size: 0.7rem; width: 50px; text-align: right; }}
.empty {{ padding: 40px; text-align: center; color: #868e96; font-size: 0.9rem; }}
.empty strong {{ display: block; margin-bottom: 4px; color: #495057; }}
.legend {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }}
.legend-item {{ display: flex; align-items: center; gap: 4px; font-size: 0.75rem; color: #495057; }}
.legend-dot {{ width: 10px; height: 10px; border-radius: 3px; }}
@media (max-width: 600px) {{
  .finding {{ flex-wrap: wrap; padding-left: 16px; }}
  .finding-location, .finding-tool {{ width: auto; }}
}}
</style>
</head>
<body>
<div id="app">
  <header>
    <h1>&#x1f512; Security Audit Report</h1>
    <span id="total-count">{total} finding{"s" if total != 1 else ""}</span>
  </header>
  <div class="legend" id="legend"></div>
  <div class="controls">
    <label for="group-by">Group by</label>
    <select id="group-by">
      <option value="tool">Tool</option>
      <option value="severity">Severity</option>
      <option value="file">File</option>
    </select>
    <label for="sort-by">Sort</label>
    <select id="sort-by">
      <option value="severity">Severity</option>
      <option value="file">File</option>
      <option value="message">Message</option>
    </select>
    <button id="sort-dir" class="btn" title="Toggle sort direction">&darr;</button>
    <input type="text" id="search" placeholder="&#x1f50d; Filter findings..." autocomplete="off">
    <button id="expand-all" class="btn">&#x25b6; Expand all</button>
    <button id="collapse-all" class="btn">&#x25bc; Collapse all</button>
  </div>
  <div id="results">
    <div class="empty"><strong>Loading...</strong></div>
  </div>
</div>
<script id="scan-data" type="application/json">{data_json}</script>
<script id="counts-data" type="application/json">{counts_json}</script>
<script>
(function() {{
  var DATA = JSON.parse(document.getElementById('scan-data').textContent);
  var COUNTS = JSON.parse(document.getElementById('counts-data').textContent);

  var SEVERITY_ORDER = {{ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, WARNING: 4, INFO: 5, UNKNOWN: 6 }};
  var SEVERITY_LABELS = {{}};
  Object.keys(SEVERITY_ORDER).forEach(function(k) {{ SEVERITY_LABELS[k] = k; }});

  var groupByEl = document.getElementById('group-by');
  var sortByEl = document.getElementById('sort-by');
  var sortDirEl = document.getElementById('sort-dir');
  var searchEl = document.getElementById('search');
  var resultsEl = document.getElementById('results');
  var legendEl = document.getElementById('legend');

  var sortAscending = false;

  function severityClass(sev) {{ return 'severity-' + (SEVERITY_ORDER[sev] !== undefined ? sev : 'UNKNOWN'); }}

  function renderLegend() {{
    var colors = {{ CRITICAL: '#c92a2a', HIGH: '#d9480f', MEDIUM: '#9c6b00', LOW: '#0b7285', INFO: '#6c757d' }};
    var html = '';
    var sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    sevs.forEach(function(s) {{
      if (COUNTS.severity[s]) {{
        html += '<span class="legend-item"><span class="legend-dot" style="background:' + colors[s] + '"></span> ' +
                s + ' (' + COUNTS.severity[s] + ')</span>';
      }}
    }});
    legendEl.innerHTML = html;
  }}

  function getGroupKey(finding, groupBy) {{
    if (groupBy === 'tool') return finding.tool || 'unknown';
    if (groupBy === 'severity') return finding.severity || 'UNKNOWN';
    if (groupBy === 'file') {{
      var f = finding.file || '';
      return f ? f.split('/').slice(0, -1).join('/') || '/' : '(no file)';
    }}
    return 'unknown';
  }}

  function getSubLabel(finding, groupBy) {{
    if (groupBy === 'tool') return finding.severity || 'UNKNOWN';
    if (groupBy === 'severity') return finding.tool || 'unknown';
    if (groupBy === 'file') return (finding.file || '').split('/').pop() || '';
    return '';
  }}

  function sortKey(finding, sortBy) {{
    if (sortBy === 'severity') return SEVERITY_ORDER[finding.severity] ?? 99;
    if (sortBy === 'file') return (finding.file || '').toLowerCase();
    if (sortBy === 'message') return (finding.message || '').toLowerCase();
    return '';
  }}

  function render() {{
    var groupBy = groupByEl.value;
    var sortBy = sortByEl.value;
    var query = searchEl.value.toLowerCase().trim();
    sortAscending = sortDirEl.textContent === '\\u2191';

    var filtered = DATA;
    if (query) {{
      filtered = DATA.filter(function(f) {{
        return (f.message || '').toLowerCase().indexOf(query) !== -1 ||
               (f.file || '').toLowerCase().indexOf(query) !== -1 ||
               (f.tool || '').toLowerCase().indexOf(query) !== -1 ||
               (f.severity || '').toLowerCase().indexOf(query) !== -1;
      }});
    }}

    var groups = {{}};
    filtered.forEach(function(f) {{
      var key = getGroupKey(f, groupBy);
      if (!groups[key]) groups[key] = [];
      groups[key].push(f);
    }});

    var groupKeys = Object.keys(groups);
    var subSort = (sortBy === 'severity') ? 'severity' : (sortBy === 'file' ? 'file' : 'message');
    groupKeys.forEach(function(k) {{
      groups[k].sort(function(a, b) {{
        var ca = sortKey(a, sortBy), cb = sortKey(b, sortBy);
        if (typeof ca === 'number') return sortAscending ? ca - cb : cb - ca;
        return sortAscending ? (ca < cb ? -1 : ca > cb ? 1 : 0) : (ca < cb ? 1 : ca > cb ? -1 : 0);
      }});
    }});

    var groupOrder = groupKeys.slice();
    if (groupBy === 'severity') {{
      groupOrder.sort(function(a, b) {{
        var oa = SEVERITY_ORDER[a] ?? 99, ob = SEVERITY_ORDER[b] ?? 99;
        return sortAscending ? oa - ob : ob - oa;
      }});
    }} else {{
      groupOrder.sort(function(a, b) {{
        var la = a.toLowerCase(), lb = b.toLowerCase();
        return sortAscending ? (la < lb ? -1 : la > lb ? 1 : 0) : (la < lb ? 1 : la > lb ? -1 : 0);
      }});
    }}

    var totalDisplay = filtered.length;
    document.getElementById('total-count').textContent =
      totalDisplay + ' finding' + (totalDisplay !== 1 ? 's' : '') +
      (totalDisplay !== DATA.length ? ' (filtered)' : '');

    var html = '';
    if (groupOrder.length === 0) {{
      html = '<div class="empty"><strong>No findings match your filter</strong>Try adjusting your search criteria</div>';
      resultsEl.innerHTML = html;
      return;
    }}

    groupOrder.forEach(function(key) {{
      var items = groups[key];
      var sev = groupBy === 'severity' ? key : (items[0] ? items[0].severity : 'UNKNOWN');
      var badgeClass = severityClass(sev);
      if (groupBy === 'tool') badgeClass = severityClass(items[0] ? items[0].severity : 'UNKNOWN');

      html += '<div class="group">';
      html += '<div class="group-header" onclick="toggleGroup(this)">';
      html += '<span class="chevron open">\\u25b6</span>';
      if (groupBy === 'severity') {{
        html += '<span class="severity-badge ' + badgeClass + '">' + key + '</span>';
      }} else {{
        html += '<span class="group-title">' + escapeHtml(key) + '</span>';
      }}
      html += '<span class="group-count">' + items.length + '</span>';
      html += '</div>';
      html += '<ul class="group-items">';

      items.forEach(function(f) {{
        var loc = (f.line ? f.file + ':' + f.line : f.file) || '(global)';
        var sevBadge = severityClass(f.severity);
        html += '<li class="finding">';
        html += '<span class="severity-badge ' + sevBadge + '">' + escapeHtml(f.severity) + '</span>';
        var displayMsg = f.message || '';
        if (displayMsg.length > 150) displayMsg = displayMsg.substring(0, 150) + '\\u2026';
        html += '<span class="finding-message">' + escapeHtml(displayMsg) + '</span>';
        html += '<span class="finding-location">' + escapeHtml(loc) + '</span>';
        if (groupBy !== 'tool') html += '<span class="finding-tool">' + escapeHtml(f.tool) + '</span>';
        html += '</li>';
      }});

      html += '</ul></div>';
    }});

    resultsEl.innerHTML = html;
  }}

  function escapeHtml(s) {{
    if (typeof s !== 'string') return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }}

  window.toggleGroup = function(el) {{
    var isCollapsed = el.classList.toggle('collapsed');
    var chevron = el.querySelector('.chevron');
    if (chevron) chevron.classList.toggle('open');
    var items = el.nextElementSibling;
    if (items) items.classList.toggle('collapsed');
  }};

  function expandAll() {{
    document.querySelectorAll('.group-header.collapsed').forEach(function(h) {{
      h.classList.remove('collapsed');
      h.querySelector('.chevron').classList.add('open');
      h.nextElementSibling.classList.remove('collapsed');
    }});
  }}

  function collapseAll() {{
    document.querySelectorAll('.group-header').forEach(function(h) {{
      if (!h.classList.contains('collapsed')) {{
        h.classList.add('collapsed');
        h.querySelector('.chevron').classList.remove('open');
        h.nextElementSibling.classList.add('collapsed');
      }}
    }});
  }}

  groupByEl.addEventListener('change', render);
  sortByEl.addEventListener('change', render);
  sortDirEl.addEventListener('click', function() {{
    sortDirEl.textContent = sortDirEl.textContent === '\\u2191' ? '\\u2193' : '\\u2191';
    render();
  }});
  searchEl.addEventListener('input', render);
  document.getElementById('expand-all').addEventListener('click', expandAll);
  document.getElementById('collapse-all').addEventListener('click', collapseAll);

  renderLegend();
  render();
}})();
</script>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    print(f"  HTML report: {output_path}")



def main():
    if len(sys.argv) < 2:
        print("Usage: aggregate_report.py <output_dir> [--fail-on LEVEL]")
        sys.exit(1)

    output_dir = Path(sys.argv[1])
    fail_on = None
    for i, arg in enumerate(sys.argv[2:], start=2):
        if arg == "--fail-on" and i + 1 < len(sys.argv):
            fail_on = sys.argv[i + 1].lower()

    parsers = {
        "gitleaks.json": parse_gitleaks,
        "hadolint.json": parse_hadolint,
        "semgrep.json": parse_semgrep,
        "bandit.json": parse_bandit,
        "safety.json": parse_safety,
        "trivy.json": parse_trivy,
    }

    all_findings = []
    tool_counts = {}
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for filename, parser in parsers.items():
        filepath = output_dir / filename
        data = load_json(filepath)
        findings = parser(data) if data is not None else []
        all_findings.extend(findings)
        tool_counts[filename.replace(".json", "")] = {
            "total": len(findings),
            "file_found": data is not None,
        }
        for f in findings:
            sev = f["severity"]
            if sev in severity_counts:
                severity_counts[sev] += 1

    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    summary = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "target": str(output_dir.resolve()),
        "tool_counts": tool_counts,
        "severity_counts": severity_counts,
        "total_findings": len(all_findings),
        "findings": all_findings,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    lines = []
    lines.append("=" * 72)
    lines.append("  SECURITY AUDIT SUMMARY")
    lines.append("=" * 72)
    lines.append(f"  Total findings: {len(all_findings)}")
    lines.append("")
    lines.append("  By severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity_counts[sev]:
            lines.append(f"    {sev:10s}: {severity_counts[sev]}")
    lines.append("")
    lines.append("  By tool:")
    for tool in ["gitleaks", "hadolint", "semgrep", "bandit", "safety", "trivy"]:
        counts = tool_counts.get(tool, {"total": 0, "file_found": False})
        if not counts["file_found"]:
            status = "skipped (no output file)"
        elif counts["total"] == 0:
            status = "PASS (0 findings)"
        else:
            plural = "" if counts["total"] == 1 else "s"
            status = f"{counts['total']} finding{plural}"
        lines.append(f"    {tool:12s}: {status}")
    lines.append("")

    if all_findings:
        lines.append("  Findings (severity descending):")
        lines.append("  " + "-" * 70)
        for f in all_findings:
            sev = f["severity"]
            msg = f["message"][:80]
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            if not loc:
                loc = "(global)"
            lines.append(f"  [{sev:8s}] {msg}")
            lines.append(f"           {f['tool']:>8s} | {loc}")
        lines.append("  " + "-" * 70)
    lines.append("=" * 72)

    report_text = "\n".join(lines)
    (output_dir / "summary.txt").write_text(report_text)
    generate_html_report(summary, output_dir / "summary.html")
    print(report_text)

    if fail_on and fail_on in THRESHOLDS:
        threshold_idx = THRESHOLDS[fail_on]
        fail_count = sum(
            c for sev, c in severity_counts.items()
            if SEVERITY_ORDER.get(sev, 99) <= threshold_idx
        )
        if fail_count > 0:
            print(f"  RESULT: FAIL ({fail_count} findings at or above '{fail_on}' severity)")
            sys.exit(1)
        else:
            print(f"  RESULT: PASS (no findings at or above '{fail_on}' severity)")
    else:
        print("  RESULT: REPORT ONLY (use --fail-on to enforce thresholds)")

    sys.exit(0)


if __name__ == "__main__":
    main()
