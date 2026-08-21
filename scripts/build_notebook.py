from __future__ import annotations

import json
from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = json.loads((ROOT / "results/public/summary.json").read_text(encoding="utf-8"))

nb = nbf.v4.new_notebook()
nb["metadata"]["kernelspec"] = {"display_name": "Python 3", "language": "python", "name": "python3"}
nb["metadata"]["language_info"] = {"name": "python", "version": "3.11+"}
nb["cells"] = [
    nbf.v4.new_markdown_cell(
        "# Digital Forensics - investigação do endpoint `/invoices/search`\n\n"
        "Notebook reproduzível para preservação, parsing, análise e exportação de resultados. "
        "A evidência bruta e as saídas restritas não são versionadas. O formato de timestamp da fonte "
        "é `YYYY-DD-MMTHH:MM`, apesar da aparência ISO; o pipeline faz o parsing explícito."
    ),
    nbf.v4.new_markdown_cell(
        "## Hipóteses\n\n"
        "- H1: houve automação em massa para consultar objetos de outros usuários.\n"
        "- H2: tokens foram reutilizados entre origens e invoices em padrão incompatível com uso humano.\n"
        "- H3: respostas de sucesso indicam um conjunto potencialmente exposto.\n"
        "- H4: o volume aumentou ao longo do trimestre.\n\n"
        "Limite: sem owner/account ID, response body e trilha de autorização não se prova acesso cross-account nem entrega de PII."
    ),
    nbf.v4.new_code_cell(
        "from pathlib import Path\n"
        "import os, sys, json\n\n"
        "ROOT = Path.cwd().resolve()\n"
        "if ROOT.name == 'notebooks': ROOT = ROOT.parent\n"
        "sys.path.insert(0, str(ROOT / 'src'))\n"
        "from meli_forensics.evidence import resolve_evidence, sha256_file\n"
        "from meli_forensics.pipeline import build_database, export_results, build_charts\n\n"
        "INPUT = Path(os.environ.get('FORENSIC_INPUT', ROOT / 'evidence' / 'three_months_logs.zip'))\n"
        "WORK = ROOT / 'work'\n"
        "PUBLIC = ROOT / 'results' / 'public'\n"
        "RESTRICTED = ROOT / 'results' / 'restricted'\n"
        "INPUT"
    ),
    nbf.v4.new_markdown_cell("## Integridade e ingestão\n\nDefina `FORENSIC_INPUT` para o ZIP ou CSV. O hash SHA-256 é calculado antes da análise."),
    nbf.v4.new_code_cell(
        "evidence = resolve_evidence(INPUT, WORK / 'evidence')\n"
        "integrity = {'path': str(evidence), 'sha256': sha256_file(evidence)}\n"
        "database = WORK / 'forensics.duckdb'\n"
        "integrity.update(build_database(evidence, database))\n"
        "integrity"
    ),
    nbf.v4.new_markdown_cell("## Análise e enriquecimento\n\nAs saídas públicas mascaram IPs e substituem tokens por fingerprints SHA-256. A pasta restrita contém os rankings completos e está no `.gitignore`."),
    nbf.v4.new_code_cell(
        "summary = export_results(database, PUBLIC, RESTRICTED, WORK / '.ipwho_cache.json')\n"
        "build_charts(PUBLIC, PUBLIC / 'charts')\n"
        "summary"
    ),
    nbf.v4.new_markdown_cell(
        "## Resultado executado desta entrega (sanitizado)\n\n"
        f"- Linhas: **{SUMMARY['overview']['row_count']:,}**\n"
        f"- Janela: **{SUMMARY['overview']['first_event']} a {SUMMARY['overview']['last_event']}**\n"
        f"- IPs automatizados de alta confiança: **{SUMMARY['suspected_exploitation']['suspect_ips']}**\n"
        f"- Requisições do cluster: **{SUMMARY['suspected_exploitation']['requests']:,}**\n"
        f"- Invoices distintos: **{SUMMARY['suspected_exploitation']['unique_invoices']:,}**\n"
        f"- HTTP 200: **{SUMMARY['suspected_exploitation']['status_200']:,}** em "
        f"**{SUMMARY['suspected_exploitation']['invoices_status_200']:,}** invoices."
    ),
    nbf.v4.new_code_cell(
        "import csv\n"
        "def read_result(name):\n"
        "    with (PUBLIC / name).open(encoding='utf-8') as f:\n"
        "        return list(csv.DictReader(f))\n\n"
        "top_20_ips = read_result('top_20_ips.csv')\n"
        "top_10_tokens = read_result('top_10_tokens.csv')\n"
        "site_impact = read_result('site_impact.csv')\n"
        "top_20_ips[:5], top_10_tokens[:3], site_impact"
    ),
    nbf.v4.new_markdown_cell(
        "## Conclusão\n\n"
        "O conjunto mostra exploração automatizada compatível com IDOR em alta confiança. A conclusão sobre "
        "divulgação de PII permanece em confiança média: HTTP 200 delimita um conjunto conservador potencialmente "
        "exposto, mas é necessário correlacionar response body, identidade do token, autorização e auditoria de dados."
    ),
]

output = ROOT / "notebooks" / "forensic_analysis.ipynb"
output.parent.mkdir(parents=True, exist_ok=True)
nbf.write(nb, output)
print(output)
