# Copyright 2026 Veritensor Security Apache 2.0
# EU AI Act Compliance Report Generator
#
# Translates Veritensor scan results into EU AI Act compliance language.
# Maps threats to specific EU AI Act articles and generates gap reports.
#
# Supports two output modes:
#   1. Compliance section added to existing HTML report (--html)
#   2. Standalone compliance gap report (--compliance eu-ai-act)

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from jinja2 import Environment

from veritensor.core.types import ScanResult
from veritensor import __version__


# ---------------------------------------------------------------------------
# EU AI Act Article Mapping
# Maps Veritensor threat categories/keywords to specific EU AI Act obligations.
# Each entry: (match_keyword, article_id, article_title, obligation_text, severity)
# ---------------------------------------------------------------------------

_EU_AI_ACT_CONTROLS: List[Dict] = [
    # Article 9 — Risk Management System
    {
        "keywords": ["CRITICAL", "OS_COMMAND_EXECUTION", "CODE_EXECUTION", "RCE",
                     "Remote Code Execution", "pickle", "UNSAFE_IMPORT"],
        "article": "Article 9",
        "title": "Risk Management System",
        "obligation": "High-risk AI systems must have a risk management system throughout the lifecycle. "
                      "Critical vulnerabilities represent failures in technical robustness.",
        "gap_action": "Remediate CRITICAL findings before production deployment. "
                      "Document remediation steps and re-scan to confirm resolution.",
        "eu_risk_level": "High Risk",
    },
    # Article 10 — Data and Data Governance
    {
        "keywords": ["PII", "GDPR", "pii_leak", "PII Leak", "Data Poisoning",
                     "Dataset Poisoning", "Prompt Injection", "prompt injection",
                     "RAG", "CREDIT_CARD", "EMAIL", "PHONE"],
        "article": "Article 10",
        "title": "Data and Data Governance",
        "obligation": "Training, validation, and testing data must be subject to appropriate governance. "
                      "Data used by high-risk AI must be free from errors and complete.",
        "gap_action": "Review flagged datasets for PII and poisoned content. "
                      "Apply data minimisation. Document data sources and governance procedures.",
        "eu_risk_level": "High Risk",
    },
    # Article 11 — Technical Documentation
    {
        "keywords": ["missing_license", "License metadata not found", "no license",
                     "INFO: License", "WARNING: License"],
        "article": "Article 11",
        "title": "Technical Documentation",
        "obligation": "Technical documentation must include details about training data, "
                      "architecture, capabilities, limitations, and performance metrics.",
        "gap_action": "Ensure all AI models include license metadata. "
                      "Generate and maintain CycloneDX AI-BOM for each artifact.",
        "eu_risk_level": "Limited Risk",
    },
    # Article 13 — Transparency and Provision of Information
    {
        "keywords": ["Hash mismatch", "hash mismatch", "MISMATCH", "identity_verified: false",
                     "identity not verified", "provenance"],
        "article": "Article 13",
        "title": "Transparency and Provision of Information",
        "obligation": "Providers of high-risk AI systems must ensure transparency about "
                      "the system's capabilities, limitations, and performance.",
        "gap_action": "Verify model provenance against HuggingFace or vendor registry. "
                      "Hash mismatches indicate unverifiable model origin — do not deploy until resolved.",
        "eu_risk_level": "High Risk",
    },
    # Article 17 — Quality Management System
    {
        "keywords": ["Typosquatting", "typosquatting", "Known malicious package",
                     "UNSAFE_IMPORT", "Supply Chain", "dependency"],
        "article": "Article 17",
        "title": "Quality Management System",
        "obligation": "Providers must have a quality management system covering all aspects "
                      "of AI system development including supply chain security.",
        "gap_action": "Audit all Python/ML dependencies for typosquatting and known CVEs. "
                      "Pin dependency versions and verify against OSV.dev.",
        "eu_risk_level": "High Risk",
    },
    # Article 26 — Obligations of Deployers
    {
        "keywords": ["MCP", "Agent Hijacking", "OS_COMMAND_EXECUTION", "DATABASE_MUTATION",
                     "UNRESTRICTED_FILE_WRITE", "LETHAL_TRIFECTA", "agentic"],
        "article": "Article 26",
        "title": "Obligations of Deployers of High-Risk AI Systems",
        "obligation": "Deployers must ensure AI systems are used in accordance with instructions "
                      "and implement human oversight measures.",
        "gap_action": "MCP tools with OS execution or database mutation capabilities must have "
                      "human-in-the-loop confirmation gates. Implement require_confirmation parameter.",
        "eu_risk_level": "High Risk",
    },
    # Article 53 — Obligations for Providers of GPAI Models
    {
        "keywords": ["Restricted license", "cc-by-nc", "agpl", "non-commercial",
                     "research-only", "toxic license"],
        "article": "Article 53",
        "title": "Obligations for Providers of General-Purpose AI Models",
        "obligation": "GPAI model providers must maintain technical documentation and "
                      "ensure license terms are compatible with intended use.",
        "gap_action": "Replace restricted-license models with commercially permissive alternatives, "
                      "or obtain explicit commercial licensing agreement.",
        "eu_risk_level": "High Risk",
    },
]

_ARTICLE_WEIGHTS = {
    "Article 9": 25,   # Risk Management — critical
    "Article 10": 20,  # Data Governance — high
    "Article 13": 15,  # Transparency — high
    "Article 26": 15,  # Deployer obligations — high (MCP/agents)
    "Article 17": 10,  # Quality Management
    "Article 53": 10,  # GPAI obligations
    "Article 11": 5,   # Technical docs — lower weight
}
_TOTAL_WEIGHT = sum(_ARTICLE_WEIGHTS.values())  # 100

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ComplianceGap:
    """A single EU AI Act compliance gap derived from a scan finding."""
    article: str
    title: str
    obligation: str
    gap_action: str
    eu_risk_level: str
    triggering_threats: List[str] = field(default_factory=list)
    affected_files: List[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Full EU AI Act compliance gap report for a set of scan results."""
    scan_date: str
    scanner_version: str
    total_artifacts: int
    passed: int
    failed: int
    gaps: List[ComplianceGap]
    clean_controls: List[str]  # Article IDs that have no findings
    readiness_score: int       # 0-100


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def _match_controls(threat: str) -> List[Dict]:
    """Returns ALL EU AI Act controls that match this threat string."""
    threat_lower = threat.lower()
    matched =[]
    for control in _EU_AI_ACT_CONTROLS:
        for kw in control["keywords"]:
            if kw.lower() in threat_lower:
                matched.append(control)
                break 
    return matched


def build_compliance_report(results: List[ScanResult]) -> ComplianceReport:
    """
    Analyses scan results and builds a structured EU AI Act compliance gap report.
    Groups findings by article. Calculates a readiness score.
    """
    gaps_by_article: Dict[str, ComplianceGap] = {}
    triggered_articles: set = set()

    for res in results:
        for threat in (res.threats or[]):
            controls = _match_controls(threat)
            for control in controls:
                article_id = control["article"]
                triggered_articles.add(article_id)

                if article_id not in gaps_by_article:
                    gaps_by_article[article_id] = ComplianceGap(
                        article=article_id,
                        title=control["title"],
                        obligation=control["obligation"],
                        gap_action=control["gap_action"],
                        eu_risk_level=control["eu_risk_level"],
                    )

                gap = gaps_by_article[article_id]
                if threat not in gap.triggering_threats:
                    gap.triggering_threats.append(threat)
                if res.file_path and res.file_path not in gap.affected_files:
                    gap.affected_files.append(res.file_path)

    # Determine which articles have no gaps
    all_article_ids = {c["article"] for c in _EU_AI_ACT_CONTROLS}
    clean_controls = sorted(all_article_ids - triggered_articles)

    # Sort gaps: High Risk first, then by article number
    sorted_gaps = sorted(
        gaps_by_article.values(),
        key=lambda g: (0 if g.eu_risk_level == "High Risk" else 1, g.article)
    )

    # Calculate weighted readiness score instead of flat percentage
    penalty = sum(_ARTICLE_WEIGHTS.get(gap.article, 10) for gap in sorted_gaps)
    readiness_score = max(0, 100 - penalty)
    
    return ComplianceReport(
        scan_date=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        scanner_version=__version__,
        total_artifacts=len(results),
        passed=sum(1 for r in results if r.status == "PASS"),
        failed=sum(1 for r in results if r.status == "FAIL"),
        gaps=sorted_gaps,
        clean_controls=clean_controls,
        readiness_score=readiness_score,
    )



def get_compliance_section_data(results: List[ScanResult]) -> Dict:
    """
    Returns data for embedding an EU AI Act section into the existing HTML report.
    Called by generate_html_report() when compliance mode is active.
    """
    report = build_compliance_report(results)
    return {
        "compliance_enabled": True,
        "compliance_score": report.readiness_score,
        "compliance_gaps": report.gaps,
        "compliance_clean": report.clean_controls,
    }


# ---------------------------------------------------------------------------
# Standalone compliance gap report (--compliance eu-ai-act)
# ---------------------------------------------------------------------------

_COMPLIANCE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EU AI Act Compliance Gap Report — Veritensor</title>
    <style>
        :root { --blue: #1a3c6e; --green: #27ae60; --red: #c0392b;
                --orange: #e67e22; --bg: #f8f9fa; --card: #ffffff; }
        * { box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: var(--bg);
               color: #333; margin: 0; padding: 24px; }
        .wrap { max-width: 1100px; margin: 0 auto; }
        
        /* Header with Button */
        .header-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px; }
        h1 { color: var(--blue); margin: 0; font-size: 1.8rem; }
        .btn-export { background: var(--blue); color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 14px; transition: 0.2s; }
        .btn-export:hover { background: #122b50; }
        .meta { color: #666; font-size: 13px; margin-bottom: 32px; margin-top: 4px; }

        /* Score card */
        .score-row { display: flex; gap: 20px; margin-bottom: 32px; flex-wrap: wrap; }
        .score-card { background: var(--card); border-radius: 10px; padding: 24px 30px;
                      box-shadow: 0 2px 8px rgba(0,0,0,.08); flex: 1; min-width: 160px;
                      text-align: center; }
        .score-card .label { font-size: 12px; text-transform: uppercase;
                             letter-spacing: .6px; color: #888; margin-bottom: 8px; }
        .score-card .val { font-size: 2.4rem; font-weight: 700; }
        .val.good  { color: var(--green); }
        .val.warn  { color: var(--orange); }
        .val.bad   { color: var(--red); }

        /* Progress bar */
        .progress-wrap { background: var(--card); border-radius: 10px;
                         padding: 24px 30px; box-shadow: 0 2px 8px rgba(0,0,0,.08);
                         margin-bottom: 32px; }
        .progress-wrap h2 { margin: 0 0 16px; font-size: 1.1rem; color: var(--blue); }
        .bar-bg { background: #e8edf2; border-radius: 99px; height: 22px; overflow: hidden; }
        .bar-fg { height: 100%; border-radius: 99px; transition: width .4s;
                  background: linear-gradient(90deg, #c0392b 0%, #e67e22 50%, #27ae60 100%);
                  background-size: 200% auto; }
        .bar-label { font-size: 13px; color: #555; margin-top: 8px; text-align: right; }

        /* Gap cards */
        h2.section { margin: 0 0 16px; font-size: 1.2rem; color: var(--blue);
                     border-bottom: 2px solid #e0e8f0; padding-bottom: 8px; }
        .gap-card { background: var(--card); border-radius: 10px;
                    box-shadow: 0 2px 8px rgba(0,0,0,.07);
                    margin-bottom: 20px; overflow: hidden; }
        .gap-header { display: flex; align-items: center; gap: 14px;
                      padding: 16px 20px; border-left: 5px solid var(--red); }
        .gap-header.limited { border-left-color: var(--orange); }
        .article-badge { background: var(--blue); color: #fff; font-weight: 700;
                         font-size: 12px; padding: 4px 10px; border-radius: 5px;
                         white-space: nowrap; }
        .gap-title { font-weight: 600; font-size: 1rem; }
        .risk-badge { margin-left: auto; font-size: 11px; padding: 3px 9px;
                      border-radius: 4px; font-weight: 600; }
        .risk-badge.high { background: #fde8e8; color: var(--red); }
        .risk-badge.limited { background: #fef3e2; color: var(--orange); }
        .gap-body { padding: 16px 20px; border-top: 1px solid #f0f0f0; }
        .gap-body p { margin: 0 0 12px; font-size: 14px; color: #444; line-height: 1.6; }
        .gap-body strong { color: #222; }
        .action-box { background: #f0f7ff; border: 1px solid #bdd6f5;
                      border-radius: 6px; padding: 12px 16px; font-size: 13px;
                      color: #1a3c6e; margin-top: 8px; }
        .action-box::before { content: "📋 Required action: "; font-weight: 700; }
        .files-list { margin: 10px 0 0; padding: 0 0 0 18px; font-size: 12px; color: #666; }
        .files-list li { margin-bottom: 3px; word-break: break-all; }
        details summary { cursor: pointer; font-size: 13px; color: #666;
                          margin-top: 10px; user-select: none; }
        details summary:hover { color: var(--blue); }
        pre.threats { background: #f8f8f8; border: 1px solid #e8e8e8;
                      border-radius: 6px; padding: 10px 12px; font-size: 11px;
                      overflow-x: auto; margin: 10px 0 0; line-height: 1.5; white-space: pre-wrap; word-wrap: break-word; }

        /* Clean controls */
        .clean-section { background: var(--card); border-radius: 10px;
                          padding: 20px 24px; box-shadow: 0 2px 8px rgba(0,0,0,.07);
                          margin-bottom: 32px; }
        .clean-section h2 { margin: 0 0 12px; font-size: 1.1rem; color: var(--green); }
        .clean-pills { display: flex; flex-wrap: wrap; gap: 8px; }
        .clean-pill { background: #eafaf1; color: var(--green); border: 1px solid #a9dfbf;
                      border-radius: 20px; padding: 4px 12px; font-size: 12px; font-weight: 600; }

        /* Footer */
        footer { text-align: center; font-size: 12px; color: #aaa; margin-top: 40px; }
        
        /* Print */
         @media print {
            @page { margin: 1cm; }
            body { 
                background: white; 
                padding: 0; 
                -webkit-print-color-adjust: exact; 
                print-color-adjust: exact; 
            }
            .wrap { max-width: 100%; padding: 0; margin: 0; }
            .btn-export { display: none !important; }
            
            /* Фиксим карточки счета */
            .score-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
            .score-card { padding: 15px; border: 1px solid #eee; }
            
            /* Фиксим карточки со статьями */
            .gap-card { page-break-inside: avoid; border: 1px solid #ddd; margin-bottom: 15px; }
            .clean-section { page-break-inside: avoid; border: 1px solid #ddd; }
            
            /* ФИКСИМ ВЫЛЕЗАЮЩИЙ ТЕКСТ УГРОЗ */
            pre.threats { 
                white-space: pre-wrap !important; 
                word-wrap: break-word !important; 
                overflow-x: hidden; 
                border: 1px solid #eee;
                background: #fafafa;
            }
            ul.files-list li { word-wrap: break-word; }
            
            details { display: block; }
            details[open] summary ~ * { display: block; }
        }
    </style>
</head>
<body>
<div class="wrap">
    <div class="header-top">
        <h1>🇪🇺 EU AI Act Compliance Gap Report</h1>
        <button class="btn-export" onclick="exportPDF()">📄 Export to PDF</button>
    </div>
    <p class="meta">
        Generated: <strong>{{ report.scan_date }}</strong> &nbsp;·&nbsp;
        Veritensor v{{ report.scanner_version }} &nbsp;·&nbsp;
        {{ report.total_artifacts }} artifact(s) scanned
        &nbsp;·&nbsp;
        <em>This report maps scan findings to EU AI Act obligations. It does not constitute legal advice.</em>
    </p>

    <!-- Score cards -->
    <div class="score-row">
        <div class="score-card">
            <div class="label">Readiness Score</div>
            <div class="val {% if report.readiness_score >= 80 %}good{% elif report.readiness_score >= 50 %}warn{% else %}bad{% endif %}">
                {{ report.readiness_score }}%
            </div>
        </div>
        <div class="score-card">
            <div class="label">Controls with Gaps</div>
            <div class="val {% if report.gaps|length == 0 %}good{% elif report.gaps|length <= 2 %}warn{% else %}bad{% endif %}">
                {{ report.gaps|length }}
            </div>
        </div>
        <div class="score-card">
            <div class="label">Controls Satisfied</div>
            <div class="val good">{{ report.clean_controls|length }}</div>
        </div>
        <div class="score-card">
            <div class="label">Artifacts Failed</div>
            <div class="val {% if report.failed == 0 %}good{% else %}bad{% endif %}">
                {{ report.failed }}
        </div>
        </div>
    </div>

    <!-- Progress bar -->
    <div class="progress-wrap">
        <h2>EU AI Act Readiness</h2>
        <div class="bar-bg">
            <div class="bar-fg" style="width: {{ report.readiness_score }}%"></div>
        </div>
        <div class="bar-label">{{ report.readiness_score }}% — {% if report.readiness_score == 100 %}All checked controls satisfied{% elif report.readiness_score >= 80 %}Minor gaps detected{% elif report.readiness_score >= 50 %}Significant gaps — action required{% else %}Critical gaps — immediate action required{% endif %}</div>
    </div>

    {% if report.gaps %}
    <h2 class="section">⚠️ Compliance Gaps ({{ report.gaps|length }})</h2>
    {% for gap in report.gaps %}
    <div class="gap-card">
        <div class="gap-header {% if gap.eu_risk_level == 'Limited Risk' %}limited{% endif %}">
            <span class="article-badge">{{ gap.article }}</span>
            <span class="gap-title">{{ gap.title }}</span>
            <span class="risk-badge {% if gap.eu_risk_level == 'High Risk' %}high{% else %}limited{% endif %}">
                {{ gap.eu_risk_level }}
            </span>
        </div>
        <div class="gap-body">
            <p><strong>Obligation:</strong> {{ gap.obligation }}</p>
            <div class="action-box">{{ gap.gap_action }}</div>
            {% if gap.affected_files %}
            <p style="margin-top:12px; margin-bottom:4px;"><strong>Affected artifacts ({{ gap.affected_files|length }}):</strong></p>
            <ul class="files-list">
                {% for f in gap.affected_files[:10] %}
                <li>{{ f | e }}</li>
                {% endfor %}
                {% if gap.affected_files|length > 10 %}
                <li><em>... and {{ gap.affected_files|length - 10 }} more</em></li>
                {% endif %}
            </ul>
            {% endif %}
            {% if gap.triggering_threats %}
            <details>
                <summary>View triggering findings ({{ gap.triggering_threats|length }})</summary>
                <pre class="threats">{% for t in gap.triggering_threats[:20] %}{{ t | e }}
{% endfor %}{% if gap.triggering_threats|length > 20 %}... and {{ gap.triggering_threats|length - 20 }} more{% endif %}</pre>
            </details>
            {% endif %}
        </div>
    </div>
    {% endfor %}
    {% else %}
    <div class="clean-section">
        <h2>✅ No compliance gaps detected</h2>
        <p>All scanned artifacts passed checks mapped to EU AI Act obligations.
           Continue scanning with each model/dataset update to maintain compliance posture.</p>
    </div>
    {% endif %}

    {% if report.clean_controls %}
    <div class="clean-section">
        <h2>✅ Satisfied Controls ({{ report.clean_controls|length }})</h2>
        <div class="clean-pills">
            {% for article in report.clean_controls %}
            <span class="clean-pill">{{ article }}</span>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    <footer>
        Generated by Veritensor v{{ report.scanner_version }} &nbsp;|&nbsp;
        veritensor.com &nbsp;|&nbsp;
        This report is for internal compliance assessment only and does not constitute legal advice.
    </footer>
</div>

<script>
    function exportPDF() {
        // Открываем все details перед печатью, чтобы угрозы попали в PDF
        document.querySelectorAll('details').forEach(detail => {
            detail.setAttribute('open', 'true');
        });
        
        // Вызываем окно печати
        window.print();
    }
</script>
</body>
</html>
"""


def generate_compliance_report(
    results: List[ScanResult],
    standard: str = "eu-ai-act",
    output_path: str = "veritensor-compliance-report.html"
) -> Tuple[str, ComplianceReport]:
    """
    Generates a standalone EU AI Act compliance gap report.
    Called when user runs: veritensor scan ./models/ --compliance eu-ai-act
    """
    if standard != "eu-ai-act":
        raise ValueError(f"Unsupported compliance standard: {standard}. Supported: eu-ai-act")

    report = build_compliance_report(results)

    env = Environment(autoescape=True)
    template = env.from_string(_COMPLIANCE_HTML)
    html_content = template.render(report=report)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path, report


def format_compliance_table(report: ComplianceReport) -> str:
    """
    Returns a compact plain-text compliance summary for CLI table output.
    Used when --compliance is passed without --html.
    """
    lines = [
        "",
        f"  🇪🇺 EU AI Act Readiness Score: {report.readiness_score}%",
        f"  Compliance gaps: {len(report.gaps)} article(s) affected",
        "",
    ]
    if report.gaps:
        lines.append("  ┌─ GAPS DETECTED ─────────────────────────────────────")
        for gap in report.gaps:
            lines.append(f"  │ {gap.article} — {gap.title} [{gap.eu_risk_level}]")
            lines.append(f"  │   Action: {gap.gap_action[:90]}{'...' if len(gap.gap_action) > 90 else ''}")
            lines.append("  │")
        lines.append("  └─────────────────────────────────────────────────────")
    else:
        lines.append("  ✅ No EU AI Act compliance gaps detected.")
    lines.append("")
    return "\n".join(lines)
