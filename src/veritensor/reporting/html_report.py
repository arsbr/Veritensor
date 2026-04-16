# Copyright 2026 Veritensor Security Apache 2.0
#
# Changes vs previous version:
#   - Severity breakdown bar chart (not just pass/fail donut)
#   - Per-file severity badge (worst severity shown next to FAIL)
#   - Scan metadata block: scanner version, timestamp, total files
#   - Copy-to-clipboard on threat text (Now includes File Path for Jira tickets!)
#   - MCP findings styled differently (purple left border) for quick visual triage
#   - Print CSS cleaned up — chart now prints correctly

import datetime
from typing import List
from jinja2 import Template
from veritensor.core.types import ScanResult
from veritensor import __version__

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Veritensor Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary: #2c3e50;
            --success: #27ae60;
            --danger: #e74c3c;
            --warning: #f39c12;
            --mcp: #8e44ad;
            --bg: #f4f7f6;
        }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }

        /* Header */
        .header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { margin: 0 0 6px 0; color: var(--primary); }
        .meta { font-size: 13px; color: #7f8c8d; line-height: 1.8; }
        .controls { display: flex; gap: 10px; align-items: center; flex-shrink: 0; }
        .btn { border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: 0.2s; font-size: 14px; }
        .btn-export { background: var(--primary); color: white; }
        .btn-export:hover { background: #1a252f; }

        /* Summary Cards */
        .summary-cards { display: flex; gap: 16px; margin-bottom: 30px; flex-wrap: wrap; }
        .card { flex: 1; min-width: 120px; background: #ecf0f1; padding: 18px 20px; border-radius: 8px; text-align: center; }
        .card h3 { margin: 0 0 8px 0; color: #7f8c8d; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
        .card .value { font-size: 32px; font-weight: bold; color: var(--primary); }
        .card.danger .value { color: var(--danger); }
        .card.success .value { color: var(--success); }
        .card.warn .value { color: var(--warning); }
        .card.mcp .value { color: var(--mcp); }

        /* Charts */
        .charts-row { display: flex; gap: 30px; margin-bottom: 40px; align-items: center; flex-wrap: wrap; }
        .chart-wrap { flex: 1; min-width: 220px; max-width: 280px; }
        .chart-wrap canvas { max-width: 100%; }
        .chart-label { text-align: center; font-size: 13px; color: #7f8c8d; margin-top: 8px; }
        .chart-bar-wrap { flex: 2; min-width: 300px; }

        /* Table */
        .search-box { width: 100%; padding: 11px 14px; margin-bottom: 16px; border: 1px solid #ccc; border-radius: 6px; font-size: 15px; box-sizing: border-box; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { padding: 11px 14px; text-align: left; border-bottom: 1px solid #eee; vertical-align: top; }
        th { background: #f8f9fa; font-weight: 600; color: #555; font-size: 13px; text-transform: uppercase; letter-spacing: 0.4px; }
        tr:hover { background: #f9f9f9; }
        .file-name { font-weight: 600; word-break: break-all; }
        .file-ext { font-size: 11px; color: #aaa; font-weight: 400; }

        /* Status + worst severity */
        .status-cell { white-space: nowrap; }
        .status-pass { color: var(--success); font-weight: bold; }
        .status-fail { color: var(--danger); font-weight: bold; }
        .worst-badge { display: inline-block; margin-left: 6px; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; color: white; vertical-align: middle; }
        .worst-CRITICAL { background: #c0392b; }
        .worst-HIGH { background: #e67e22; }
        .worst-MEDIUM { background: #d4ac0d; color: #333; }
        .worst-LOW { background: #3498db; }

        /* Threat list */
        .threat-list { margin: 0; padding: 0; list-style: none; }
        .threat-item { margin-bottom: 6px; padding: 7px 10px; background: #fff5f5; border-left: 4px solid var(--danger); border-radius: 4px; cursor: pointer; transition: background 0.15s; position: relative; }
        .threat-item:hover { background: #fde8e8; }
        .threat-item.mcp { background: #f5effe; border-left-color: var(--mcp); }
        .threat-item.mcp:hover { background: #ede0fa; }
        .sev-badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; color: white; margin-right: 6px; }
        .sev-CRITICAL { background: #c0392b; }
        .sev-HIGH { background: #e67e22; }
        .sev-MEDIUM { background: #d4ac0d; color: #333; }
        .sev-LOW { background: #3498db; }
        .sev-MCP { background: var(--mcp); }
        .copy-hint { font-size: 11px; color: #aaa; float: right; margin-top: 2px; }

        /* Print */
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; max-width: 100%; padding: 0; }
            .btn, .search-box, .copy-hint { display: none !important; }
            .charts-row { page-break-inside: avoid; }
            tr { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
<div class="container">

    <div class="header">
        <div>
            <h1>🛡️ Veritensor Security Report</h1>
            <div class="meta">
                Generated: <strong>{{ date }}</strong> &nbsp;·&nbsp;
                Scanner: <strong>veritensor v{{ version }}</strong> &nbsp;·&nbsp;
                Files scanned: <strong>{{ total }}</strong>
            </div>
        </div>
        <div class="controls">
            <button class="btn btn-export" onclick="window.print()">📄 Export to PDF</button>
        </div>
    </div>

    <!-- Summary cards -->
    <div class="summary-cards">
        <div class="card">
            <h3>Total Files</h3>
            <div class="value">{{ total }}</div>
        </div>
        <div class="card success">
            <h3>Passed</h3>
            <div class="value">{{ passed }}</div>
        </div>
        <div class="card danger">
            <h3>Failed</h3>
            <div class="value">{{ failed }}</div>
        </div>
        <div class="card danger">
            <h3>Critical</h3>
            <div class="value">{{ sev_counts.CRITICAL }}</div>
        </div>
        <div class="card warn">
            <h3>High</h3>
            <div class="value">{{ sev_counts.HIGH }}</div>
        </div>
        <div class="card mcp">
            <h3>MCP Risks</h3>
            <div class="value">{{ mcp_count }}</div>
        </div>
    </div>

    <!-- Charts -->
    <div class="charts-row">
        <div class="chart-wrap">
            <canvas id="donutChart"></canvas>
            <div class="chart-label">Pass / Fail</div>
        </div>
        <div class="chart-bar-wrap">
            <canvas id="sevChart" height="140"></canvas>
        </div>
    </div>

    <!-- Findings table -->
    <h2 style="margin-bottom:12px;">Detailed Findings</h2>
    <input type="text" id="searchInput" class="search-box"
           onkeyup="filterTable()"
           placeholder="Search by file name, threat type, or severity...">

    <table id="reportTable">
        <thead>
            <tr>
                <th>File</th>
                <th>Status</th>
                <th>Threats Detected</th>
            </tr>
        </thead>
        <tbody>
        {% for res in results %}
        <tr>
            <td>
                <div class="file-name">
                    {{ res.file_path.split('/')[-1].rsplit('.', 1)[0] }}
                    <span class="file-ext">.{{ res.file_path.split('/')[-1].rsplit('.', 1)[-1] if '.' in res.file_path.split('/')[-1] else '' }}</span>
                </div>
                <div style="font-size:11px;color:#aaa;margin-top:2px;">{{ res.file_path }}</div>
            </td>
            <td class="status-cell">
                <span class="{% if res.status == 'PASS' %}status-pass{% else %}status-fail{% endif %}">
                    {{ res.status }}
                </span>
                {% if res.status == 'FAIL' and res.threats %}
                    {% set worst = namespace(val='LOW') %}
                    {% for t in res.threats %}
                        {% if 'CRITICAL' in t %}{% set worst.val = 'CRITICAL' %}
                        {% elif 'HIGH' in t and worst.val != 'CRITICAL' %}{% set worst.val = 'HIGH' %}
                        {% elif 'MEDIUM' in t and worst.val not in ['CRITICAL','HIGH'] %}{% set worst.val = 'MEDIUM' %}
                        {% endif %}
                    {% endfor %}
                    <span class="worst-badge worst-{{ worst.val }}">{{ worst.val }}</span>
                {% endif %}
            </td>
            <td>
                {% if res.threats %}
                <ul class="threat-list">
                {% for threat in res.threats %}
                    {% set is_mcp = 'MCP' in threat or 'Agent Hijacking' in threat %}
                    <li class="threat-item{% if is_mcp %} mcp{% endif %}"
                        data-file="{{ res.file_path | e }}"
                        data-threat="{{ threat | e }}"
                        onclick="copyThreat(this)"
                        title="Click to copy">
                        {% if is_mcp %}
                            <span class="sev-badge sev-MCP">MCP</span>
                        {% elif 'CRITICAL' in threat %}<span class="sev-badge sev-CRITICAL">CRITICAL</span>
                        {% elif 'HIGH' in threat %}<span class="sev-badge sev-HIGH">HIGH</span>
                        {% elif 'MEDIUM' in threat %}<span class="sev-badge sev-MEDIUM">MEDIUM</span>
                        {% elif 'LOW' in threat %}<span class="sev-badge sev-LOW">LOW</span>
                        {% endif %}
                        {{ threat
                            | replace('CRITICAL: ', '')
                            | replace('HIGH: ', '')
                            | replace('MEDIUM: ', '')
                            | replace('LOW: ', '') }}
                        <span class="copy-hint">📋 copy</span>
                    </li>
                {% endfor %}
                </ul>
                {% else %}
                    <span style="color:#bbb;font-size:13px;">No threats detected</span>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
        </tbody>
    </table>

</div>

<script>
// ── Charts ──────────────────────────────────────────────────
const donut = new Chart(document.getElementById('donutChart'), {
    type: 'doughnut',
    data: {
        labels: ['Passed', 'Failed'],
        datasets: [{ data: [{{ passed }}, {{ failed }}],
            backgroundColor: ['#27ae60', '#e74c3c'], borderWidth: 0 }]
    },
    options: { responsive: true, maintainAspectRatio: true,
        plugins: { legend: { position: 'bottom', labels: { font: { size: 12 } } } } }
});

const sevBar = new Chart(document.getElementById('sevChart'), {
    type: 'bar',
    data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'MCP Risks'],
        datasets: [{
            label: 'Threat count',
            data:[{{ sev_counts.CRITICAL }}, {{ sev_counts.HIGH }},
                   {{ sev_counts.MEDIUM }}, {{ sev_counts.LOW }}, {{ mcp_count }}],
            backgroundColor:['#c0392b', '#e67e22', '#d4ac0d', '#3498db', '#8e44ad'],
            borderRadius: 4
        }]
    },
    options: {
        responsive: true,
        plugins: { legend: { display: false },
                   title: { display: true, text: 'Threats by Severity', font: { size: 13 } } },
        scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } }
    }
});

// ── Search ──────────────────────────────────────────────────
function filterTable() {
    const filter = document.getElementById('searchInput').value.toUpperCase();
    document.querySelectorAll('#reportTable tbody tr').forEach(row => {
        row.style.display = row.textContent.toUpperCase().includes(filter) ? '' : 'none';
    });
}

// ── Copy to clipboard (UPDATED FOR JIRA) ────────────────────
function copyThreat(el) {
    // Извлекаем данные из безопасных data-атрибутов
    const fileName = el.getAttribute('data-file');
    const threatText = el.getAttribute('data-threat');
    
    // Форматируем текст идеально для вставки в Jira/Slack
    const textToCopy = `File: ${fileName}\nThreat: ${threatText}`;
    
    navigator.clipboard.writeText(textToCopy).then(() => {
        const hint = el.querySelector('.copy-hint');
        hint.textContent = '✓ copied';
        setTimeout(() => { hint.textContent = '📋 copy'; }, 1500);
    });
}
</script>
</body>
</html>
"""


def _count_severities(results: List[ScanResult]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for res in results:
        for threat in (res.threats or[]):
            for sev in counts:
                if sev in threat:
                    counts[sev] += 1
                    break
    return counts


def _count_mcp(results: List[ScanResult]) -> int:
    total = 0
    for res in results:
        for threat in (res.threats or[]):
            if "MCP" in threat or "Agent Hijacking" in threat:
                total += 1
    return total


def generate_html_report(
    results: List[ScanResult],
    output_path: str = "veritensor-report.html"
) -> str:
    """Generates a standalone HTML report for CISOs and Auditors."""
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    sev_counts = _count_severities(results)
    mcp_count = _count_mcp(results)

    for res in results:
        if res.file_path:
            res.file_path = res.file_path.replace("\\", "/")

    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        date=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        version=__version__,
        total=len(results),
        passed=passed,
        failed=failed,
        sev_counts=sev_counts,
        mcp_count=mcp_count,
        results=results
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path
