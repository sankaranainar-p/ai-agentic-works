"""
audit/prov_receipt.py — W3C PROV-DM Audit Receipts for Compliance Decisions.

Generates provenance graphs compliant with the W3C PROV Data Model (PROV-DM)
and PROV-JSON representation standards (Contribution C2).

Tracks:
  - Entities: InputSnippet (with SHA-256 integrity hash), RulePack,
    DetectorFinding, and ArbitrationReceipt.
  - Activities: StaticScanActivity, LLMInferenceActivity, CostArbitrationActivity.
  - Agents: StaticDetectorAgent, LLMDetectorAgent, ArbitratorAgent.
  - Relations: prov:wasGeneratedBy, prov:used, prov:wasAssociatedWith, prov:wasDerivedFrom.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from api.schemas import ComplianceFinding


class AuditReceiptBuilder:
    """Builder for W3C PROV-DM provenance receipts of compliance arbitration decisions."""

    def __init__(
        self,
        code: str,
        file_path: str = "untitled",
        regulation: str = "GDPR",
        rule_pack_path: Optional[str] = None,
    ) -> None:
        self.code = code
        self.file_path = file_path
        self.regulation = regulation
        self.rule_pack_path = rule_pack_path or f"rules/{regulation.lower()}.json"

        # Cryptographic digest of source code snippet
        self.code_sha256 = hashlib.sha256(code.encode("utf-8")).hexdigest()
        self.receipt_id = str(uuid.uuid4())

        self.static_findings: List[ComplianceFinding] = []
        self.llm_findings: List[ComplianceFinding] = []
        self.arbitrated_findings: List[ComplianceFinding] = []

        self.routing_action: str = "neural"
        self.status: str = "completed"
        self.estimated_risk: Optional[float] = None
        self.cost_parameters: Dict[str, float] = {}
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def set_static_results(self, findings: Sequence[ComplianceFinding]) -> AuditReceiptBuilder:
        self.static_findings = list(findings)
        return self

    def set_llm_results(self, findings: Sequence[ComplianceFinding]) -> AuditReceiptBuilder:
        self.llm_findings = list(findings)
        return self

    def set_arbitration_decision(
        self,
        findings: Sequence[ComplianceFinding],
        routing_action: str,
        status: str = "completed",
        estimated_risk: Optional[float] = None,
        cost_parameters: Optional[Dict[str, float]] = None,
    ) -> AuditReceiptBuilder:
        self.arbitrated_findings = list(findings)
        self.routing_action = routing_action
        self.status = status
        self.estimated_risk = estimated_risk
        if cost_parameters:
            self.cost_parameters = dict(cost_parameters)
        return self

    def to_prov_json(self) -> Dict[str, Any]:
        """Serialize the complete provenance graph to standard W3C PROV-JSON."""
        prefix = {
            "prov": "http://www.w3.org/ns/prov#",
            "cacc": "https://compliance-as-code.org/prov#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
        }

        short_hash = self.code_sha256[:12]
        snippet_id = f"cacc:InputSnippet_{short_hash}"
        rule_pack_id = f"cacc:RulePack_{self.regulation}"
        receipt_entity_id = f"cacc:ArbitrationReceipt_{self.receipt_id[:8]}"

        static_act_id = f"cacc:StaticScanActivity_{self.receipt_id[:8]}"
        llm_act_id = f"cacc:LLMInferenceActivity_{self.receipt_id[:8]}"
        arbitrate_act_id = f"cacc:CostArbitrationActivity_{self.receipt_id[:8]}"

        static_agent_id = "cacc:StaticDetectorAgent"
        llm_agent_id = "cacc:LLMDetectorAgent"
        arbitrator_agent_id = "cacc:ArbitratorAgent"

        # 1. Entities
        entities: Dict[str, Dict[str, Any]] = {
            snippet_id: {
                "prov:type": "cacc:InputSnippet",
                "cacc:sha256": self.code_sha256,
                "cacc:filePath": self.file_path,
                "cacc:charLength": len(self.code),
            },
            rule_pack_id: {
                "prov:type": "cacc:RulePack",
                "cacc:regulation": self.regulation,
                "cacc:rulePackPath": self.rule_pack_path,
            },
            receipt_entity_id: {
                "prov:type": "cacc:ArbitrationReceipt",
                "cacc:receiptId": self.receipt_id,
                "cacc:routingAction": self.routing_action,
                "cacc:status": self.status,
                "cacc:estimatedRisk": self.estimated_risk,
                "cacc:findingCount": len(self.arbitrated_findings),
                "cacc:timestamp": self.timestamp,
            },
        }

        # Add findings entities
        finding_entity_ids: List[str] = []
        for idx, f in enumerate(self.arbitrated_findings):
            fid = f"cacc:Finding_{f.violation_id[:8]}"
            finding_entity_ids.append(fid)
            entities[fid] = {
                "prov:type": "cacc:DetectorFinding",
                "cacc:ruleId": f.rule_id,
                "cacc:severity": f.severity,
                "cacc:title": f.title,
                "cacc:lineStart": f.line_start,
                "cacc:lineEnd": f.line_end,
            }

        # 2. Activities
        activities: Dict[str, Dict[str, Any]] = {
            static_act_id: {
                "prov:type": "cacc:StaticScanActivity",
                "prov:startTime": self.timestamp,
                "cacc:findingsFound": len(self.static_findings),
            },
            llm_act_id: {
                "prov:type": "cacc:LLMInferenceActivity",
                "prov:startTime": self.timestamp,
                "cacc:findingsFound": len(self.llm_findings),
            },
            arbitrate_act_id: {
                "prov:type": "cacc:CostArbitrationActivity",
                "cacc:action": self.routing_action,
                "cacc:status": self.status,
                "cacc:costParameters": self.cost_parameters,
            },
        }

        # 3. Agents
        agents: Dict[str, Dict[str, Any]] = {
            static_agent_id: {
                "prov:type": "prov:SoftwareAgent",
                "cacc:component": "StaticScannerDetector",
                "cacc:paradigm": "symbolic_ast_regex",
            },
            llm_agent_id: {
                "prov:type": "prov:SoftwareAgent",
                "cacc:component": "LLMDetector",
                "cacc:paradigm": "neural_generative",
            },
            arbitrator_agent_id: {
                "prov:type": "prov:SoftwareAgent",
                "cacc:component": "CostSensitiveRejectRouter",
                "cacc:paradigm": "tri_choice_deferral",
            },
        }

        # 4. Relations: wasGeneratedBy
        was_generated_by: Dict[str, Dict[str, Any]] = {
            "_:wgb_receipt": {
                "prov:entity": receipt_entity_id,
                "prov:activity": arbitrate_act_id,
            }
        }
        for idx, fid in enumerate(finding_entity_ids):
            act = static_act_id if self.routing_action == "symbolic" else llm_act_id
            was_generated_by[f"_:wgb_f_{idx}"] = {
                "prov:entity": fid,
                "prov:activity": act,
            }

        # 5. Relations: used
        used: Dict[str, Dict[str, Any]] = {
            "_:u_static_snippet": {
                "prov:activity": static_act_id,
                "prov:entity": snippet_id,
            },
            "_:u_static_rules": {
                "prov:activity": static_act_id,
                "prov:entity": rule_pack_id,
            },
            "_:u_llm_snippet": {
                "prov:activity": llm_act_id,
                "prov:entity": snippet_id,
            },
            "_:u_arb_receipt": {
                "prov:activity": arbitrate_act_id,
                "prov:entity": snippet_id,
            },
        }

        # 6. Relations: wasAssociatedWith
        was_associated_with: Dict[str, Dict[str, Any]] = {
            "_:waw_static": {
                "prov:activity": static_act_id,
                "prov:agent": static_agent_id,
            },
            "_:waw_llm": {
                "prov:activity": llm_act_id,
                "prov:agent": llm_agent_id,
            },
            "_:waw_arb": {
                "prov:activity": arbitrate_act_id,
                "prov:agent": arbitrator_agent_id,
            },
        }

        # 7. Relations: wasDerivedFrom
        was_derived_from: Dict[str, Dict[str, Any]] = {
            "_:wdf_receipt_snippet": {
                "prov:generatedEntity": receipt_entity_id,
                "prov:usedEntity": snippet_id,
            },
            "_:wdf_receipt_rules": {
                "prov:generatedEntity": receipt_entity_id,
                "prov:usedEntity": rule_pack_id,
            },
        }

        return {
            "prefix": prefix,
            "entity": entities,
            "activity": activities,
            "agent": agents,
            "wasGeneratedBy": was_generated_by,
            "used": used,
            "wasAssociatedWith": was_associated_with,
            "wasDerivedFrom": was_derived_from,
        }

    def to_json(self, indent: int = 2) -> str:
        """Return serialized W3C PROV-JSON string."""
        return json.dumps(self.to_prov_json(), indent=indent)
