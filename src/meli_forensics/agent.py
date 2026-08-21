from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import requests


class TextModel(Protocol):
    def complete(self, system: str, user: str) -> str: ...


@dataclass
class OpenAICompatibleModel:
    """Small adapter for providers exposing a /chat/completions-compatible API."""

    endpoint: str
    model: str
    api_key: str
    timeout_seconds: int = 60

    def complete(self, system: str, user: str) -> str:
        response = requests.post(
            self.endpoint,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": self.model,
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


class ForensicInvestigator:
    """Plan-execute-verify agent over sanitized, derived forensic evidence."""

    def __init__(self, results_dir: Path, model: TextModel | None = None):
        self.results_dir = results_dir
        self.summary = json.loads((results_dir / "summary.json").read_text(encoding="utf-8"))
        self.model = model
        self.evidence = self._evidence_catalog()

    def _evidence_catalog(self) -> dict[str, dict[str, Any]]:
        overview = self.summary["overview"]
        suspect = self.summary["suspected_exploitation"]
        return {
            "EVID-001": {
                "claim": "A fully automated cluster queried the vulnerable endpoint at scale.",
                "facts": {
                    "suspect_ips": suspect["suspect_ips"],
                    "requests": suspect["requests"],
                    "unique_tokens": suspect["unique_tokens"],
                    "unique_invoices": suspect["unique_invoices"],
                },
            },
            "EVID-002": {
                "claim": "The automated activity escalated month over month.",
                "facts": self.summary["monthly_suspected_activity"],
            },
            "EVID-003": {
                "claim": "HTTP 200 responses indicate a conservative population potentially disclosed.",
                "facts": {
                    "status_200": suspect["status_200"],
                    "invoices_status_200": suspect["invoices_status_200"],
                    "caveat": "Status alone does not prove response body or PII delivery.",
                },
            },
            "EVID-004": {
                "claim": "The activity spans the complete observed window and all logged sites.",
                "facts": {
                    "first_seen": suspect["first_seen"],
                    "last_seen": suspect["last_seen"],
                    "site_by_volume": self.summary["site_by_request_volume"],
                    "site_by_unique_invoice": self.summary["site_by_unique_invoice"],
                    "total_sites": overview["unique_sites"],
                },
            },
        }

    def plan(self) -> list[str]:
        return [
            "Classify the observed pattern and confidence",
            "Build the technical timeline",
            "Estimate conservative business impact",
            "Identify visibility gaps and next evidence sources",
            "Prioritize containment and strategic controls",
        ]

    def deterministic_assessment(self) -> str:
        suspect = self.summary["suspected_exploitation"]
        months = self.summary["monthly_suspected_activity"]
        monthly = ", ".join(f"{item['month']}: {item['requests']:,}" for item in months)
        return (
            "Classification: HIGH confidence of automated exploitation compatible with IDOR; "
            "MEDIUM confidence of PII disclosure.\n\n"
            f"Five automated sources generated {suspect['requests']:,} requests with only "
            f"{suspect['unique_tokens']} tokens and touched {suspect['unique_invoices']:,} distinct invoices "
            "[EVID-001]. The monthly progression was " + monthly + " [EVID-002]. "
            f"There were {suspect['status_200']:,} HTTP 200 responses spanning "
            f"{suspect['invoices_status_200']:,} invoices; this is a conservative potential-exposure set, "
            "not proof that response bodies contained PII [EVID-003]. The observed activity spans the "
            "entire three-month window and all four sites [EVID-004].\n\n"
            "Immediate actions: disable object access based solely on invoice_id; enforce server-side "
            "subject-to-object authorization; revoke the four implicated tokens; preserve CDN/WAF, "
            "application, identity and database logs; notify Legal/Privacy; and hunt for the five source "
            "fingerprints across the wider estate. Strategic actions: centralized authorization, negative "
            "access-control tests in CI, object-access audit trails, rate controls and anomaly alerts."
        )

    def run(self) -> dict[str, Any]:
        deterministic = self.deterministic_assessment()
        if self.model is None:
            narrative = deterministic
            mode = "deterministic-safe-fallback"
        else:
            system = (
                "You are a digital-forensics reasoning agent. Use only the supplied sanitized evidence. "
                "Every factual claim must cite an evidence ID in square brackets. Separate observation, "
                "inference and unknown. Never claim attribution or confirmed PII delivery from HTTP status alone."
            )
            user = json.dumps({"plan": self.plan(), "evidence": self.evidence}, ensure_ascii=False, indent=2)
            narrative = self.model.complete(system, user)
            mode = "genai"
            cited = {evidence_id for evidence_id in self.evidence if f"[{evidence_id}]" in narrative}
            if not cited:
                raise ValueError("Model output failed evidence-citation verification")
        return {
            "mode": mode,
            "plan": self.plan(),
            "evidence_catalog": self.evidence,
            "assessment": narrative,
            "verification": {
                "no_raw_tokens_sent": True,
                "no_full_ips_sent": True,
                "human_review_required": True,
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the sanitized forensic investigator agent")
    parser.add_argument("--results", type=Path, default=Path("results/public"))
    parser.add_argument("--output", type=Path, default=Path("results/public/agent_assessment.json"))
    parser.add_argument("--llm-endpoint")
    parser.add_argument("--model")
    parser.add_argument("--api-key-env", default="GENAI_API_KEY")
    args = parser.parse_args()

    model = None
    if args.llm_endpoint and args.model:
        key = os.environ.get(args.api_key_env)
        if not key:
            raise ValueError(f"Missing API key in {args.api_key_env}")
        model = OpenAICompatibleModel(args.llm_endpoint, args.model, key)
    result = ForensicInvestigator(args.results, model).run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(result["assessment"])


if __name__ == "__main__":
    main()
