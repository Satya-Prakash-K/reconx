"""AI Triage Pipeline — automated finding analysis, dedup, scoring and prioritization.

Pipeline stages:
1. Deduplication (semantic + structural)
2. Similarity clustering
3. CWE classification
4. CVSS estimation
5. OWASP mapping
6. Exploitability scoring
7. Impact prediction
8. Severity auto-classification
9. Priority ranking
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

import structlog

logger = structlog.get_logger(__name__)


class TriagedFinding(BaseModel):
    """A fully triaged vulnerability finding."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    original_id: str = ""
    workspace_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "info"
    category: str = ""
    affected_url: str = ""
    param: str = ""
    confidence: float = 0.5
    # Triage enrichments
    cwe_id: str = ""
    cwe_name: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    owasp_category: str = ""
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    priority_rank: int = 0
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    cluster_id: Optional[str] = None
    root_cause: str = ""
    suggested_fix: str = ""
    ai_summary: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    source_tool: str = ""
    triaged_at: Optional[datetime] = None


class TriagePipeline:
    """Full AI triage pipeline for vulnerability findings."""

    def __init__(self):
        self.dedup_engine = DeduplicationEngine()
        self.cluster_engine = SimilarityClusterer()
        self.cwe_classifier = CWEClassifier()
        self.cvss_estimator = CVSSEstimator()
        self.owasp_mapper = OWASPMapper()
        self.exploit_scorer = ExploitabilityScorer()
        self.impact_predictor = ImpactPredictor()
        self.severity_classifier = SeverityClassifier()

    async def triage(self, findings: list[dict[str, Any]], workspace_id: str) -> list[TriagedFinding]:
        """Run the complete triage pipeline on a batch of findings."""
        logger.info("Triage pipeline started", count=len(findings), workspace=workspace_id)

        # Stage 1: Convert to TriagedFinding objects
        triaged = [self._to_triaged(f, workspace_id) for f in findings]

        # Stage 2: Deduplication
        triaged = await self.dedup_engine.deduplicate(triaged)
        unique = [f for f in triaged if not f.is_duplicate]
        logger.info("Dedup complete", total=len(triaged), unique=len(unique), dupes=len(triaged)-len(unique))

        # Stage 3: Similarity clustering
        unique = await self.cluster_engine.cluster(unique)

        # Stage 4: CWE classification
        for f in unique:
            cwe = self.cwe_classifier.classify(f)
            f.cwe_id = cwe["id"]
            f.cwe_name = cwe["name"]

        # Stage 5: CVSS estimation
        for f in unique:
            cvss = self.cvss_estimator.estimate(f)
            f.cvss_score = cvss["score"]
            f.cvss_vector = cvss["vector"]

        # Stage 6: OWASP mapping
        for f in unique:
            f.owasp_category = self.owasp_mapper.map(f)

        # Stage 7: Exploitability scoring
        for f in unique:
            f.exploitability_score = self.exploit_scorer.score(f)

        # Stage 8: Impact prediction
        for f in unique:
            f.impact_score = self.impact_predictor.predict(f)

        # Stage 9: Severity auto-classification
        for f in unique:
            f.severity = self.severity_classifier.classify(f)

        # Stage 10: Priority ranking
        unique.sort(key=lambda f: (f.cvss_score * 0.3 + f.exploitability_score * 0.3 +
                                    f.impact_score * 0.2 + f.confidence * 0.2), reverse=True)
        for rank, f in enumerate(unique, 1):
            f.priority_rank = rank
            f.triaged_at = datetime.now(timezone.utc)

        logger.info("Triage complete", findings=len(unique),
                     critical=sum(1 for f in unique if f.severity == "critical"),
                     high=sum(1 for f in unique if f.severity == "high"))
        return triaged  # Return all (including marked duplicates)

    def _to_triaged(self, raw: dict, workspace_id: str) -> TriagedFinding:
        return TriagedFinding(
            original_id=raw.get("id", ""),
            workspace_id=workspace_id,
            title=raw.get("title", ""),
            description=raw.get("description", ""),
            severity=raw.get("severity", "info"),
            category=raw.get("category", ""),
            affected_url=raw.get("affected_url", ""),
            param=raw.get("param", ""),
            confidence=raw.get("confidence", 0.5),
            evidence=raw.get("evidence", {}),
            source_tool=raw.get("source_tool", ""),
        )


class DeduplicationEngine:
    """Detects duplicate findings using structural + semantic hashing."""

    def _structural_hash(self, f: TriagedFinding) -> str:
        """Create a structural fingerprint for exact dedup."""
        content = f"{f.category}|{f.affected_url}|{f.param}|{f.title}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    async def deduplicate(self, findings: list[TriagedFinding]) -> list[TriagedFinding]:
        """Mark duplicates using structural hashing + semantic similarity."""
        seen: dict[str, str] = {}  # hash -> finding.id

        for f in findings:
            h = self._structural_hash(f)
            if h in seen:
                f.is_duplicate = True
                f.duplicate_of = seen[h]
            else:
                seen[h] = f.id

        # Semantic dedup via embeddings (if available)
        try:
            from src.ai.embeddings import EmbeddingPipeline
            pipeline = EmbeddingPipeline()
            texts = [f"{f.title} {f.description} {f.affected_url}" for f in findings]
            embeddings = await pipeline.embed_batch(texts)

            if embeddings is not None:
                from sklearn.metrics.pairwise import cosine_similarity
                import numpy as np
                sim_matrix = cosine_similarity(np.array(embeddings))

                for i in range(len(findings)):
                    if findings[i].is_duplicate:
                        continue
                    for j in range(i + 1, len(findings)):
                        if findings[j].is_duplicate:
                            continue
                        if sim_matrix[i][j] > 0.92:
                            findings[j].is_duplicate = True
                            findings[j].duplicate_of = findings[i].id
        except Exception as e:
            logger.debug("Semantic dedup unavailable", error=str(e))

        return findings


class SimilarityClusterer:
    """Groups similar findings into clusters for batch triage."""

    async def cluster(self, findings: list[TriagedFinding]) -> list[TriagedFinding]:
        """Cluster findings by similarity."""
        # Simple category-based clustering
        clusters: dict[str, str] = {}
        for f in findings:
            key = f"{f.category}:{f.affected_url.split('?')[0] if '?' in f.affected_url else f.affected_url}"
            if key not in clusters:
                clusters[key] = str(uuid.uuid4())[:8]
            f.cluster_id = clusters[key]
        return findings


class CWEClassifier:
    """Maps findings to CWE (Common Weakness Enumeration) entries."""

    CWE_MAP = {
        "xss": {"id": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation"},
        "sqli": {"id": "CWE-89", "name": "Improper Neutralization of Special Elements used in an SQL Command"},
        "ssrf": {"id": "CWE-918", "name": "Server-Side Request Forgery"},
        "idor": {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key"},
        "auth_flaw": {"id": "CWE-287", "name": "Improper Authentication"},
        "authz_bypass": {"id": "CWE-862", "name": "Missing Authorization"},
        "jwt_weakness": {"id": "CWE-347", "name": "Improper Verification of Cryptographic Signature"},
        "graphql": {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor"},
        "file_upload": {"id": "CWE-434", "name": "Unrestricted Upload of File with Dangerous Type"},
        "open_redirect": {"id": "CWE-601", "name": "URL Redirection to Untrusted Site"},
        "cors_misconfig": {"id": "CWE-942", "name": "Permissive Cross-domain Policy with Untrusted Domains"},
        "api_security": {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor"},
        "data_exposure": {"id": "CWE-200", "name": "Exposure of Sensitive Information to an Unauthorized Actor"},
        "misconfiguration": {"id": "CWE-16", "name": "Configuration"},
        "cloud_exposure": {"id": "CWE-284", "name": "Improper Access Control"},
    }

    def classify(self, finding: TriagedFinding) -> dict[str, str]:
        return self.CWE_MAP.get(finding.category, {"id": "CWE-0", "name": "Unknown"})


class CVSSEstimator:
    """Estimates CVSS v3.1 scores from finding characteristics."""

    def estimate(self, finding: TriagedFinding) -> dict[str, Any]:
        """Estimate CVSS base score and vector string."""
        # Attack Vector (AV)
        av = "N"  # Network — all web vulns

        # Attack Complexity (AC)
        ac = "L" if finding.confidence > 0.7 else "H"

        # Privileges Required (PR)
        if finding.category in ("auth_flaw", "authz_bypass"):
            pr = "N"
        elif finding.category in ("idor",):
            pr = "L"
        else:
            pr = "N"

        # User Interaction (UI)
        ui = "R" if finding.category in ("xss", "open_redirect") else "N"

        # Scope (S)
        s = "C" if finding.category in ("xss", "ssrf") else "U"

        # CIA Impact
        if finding.category in ("sqli", "cloud_exposure", "data_exposure"):
            c, i_val, a = "H", "H", "H"
        elif finding.category in ("xss", "open_redirect"):
            c, i_val, a = "L", "L", "N"
        elif finding.category in ("ssrf", "idor", "authz_bypass"):
            c, i_val, a = "H", "L", "N"
        elif finding.category in ("auth_flaw", "jwt_weakness"):
            c, i_val, a = "H", "H", "N"
        else:
            c, i_val, a = "L", "N", "N"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i_val}/A:{a}"

        # Calculate approximate score
        score = self._calculate_score(av, ac, pr, ui, s, c, i_val, a)

        return {"score": round(score, 1), "vector": vector}

    def _calculate_score(self, av, ac, pr, ui, s, c, i_val, a) -> float:
        """Approximate CVSS 3.1 base score calculation."""
        av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_scores = {"L": 0.77, "H": 0.44}
        pr_scores_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_scores_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_scores = {"N": 0.85, "R": 0.62}
        cia_scores = {"H": 0.56, "L": 0.22, "N": 0.0}

        pr_map = pr_scores_changed if s == "C" else pr_scores_unchanged
        exploitability = 8.22 * av_scores[av] * ac_scores[ac] * pr_map[pr] * ui_scores[ui]
        impact_sub = 1 - ((1 - cia_scores[c]) * (1 - cia_scores[i_val]) * (1 - cia_scores[a]))

        if s == "U":
            impact = 6.42 * impact_sub
        else:
            impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15

        if impact <= 0:
            return 0.0

        if s == "U":
            score = min(10, exploitability + impact)
        else:
            score = min(10, 1.08 * (exploitability + impact))

        return round(score * 10) / 10


class OWASPMapper:
    """Maps findings to OWASP Top 10 (2021) categories."""

    OWASP_MAP = {
        "sqli": "A03:2021-Injection",
        "xss": "A03:2021-Injection",
        "ssrf": "A10:2021-SSRF",
        "idor": "A01:2021-Broken Access Control",
        "auth_flaw": "A07:2021-Identification and Authentication Failures",
        "authz_bypass": "A01:2021-Broken Access Control",
        "jwt_weakness": "A02:2021-Cryptographic Failures",
        "graphql": "A01:2021-Broken Access Control",
        "file_upload": "A04:2021-Insecure Design",
        "open_redirect": "A01:2021-Broken Access Control",
        "cors_misconfig": "A05:2021-Security Misconfiguration",
        "api_security": "A05:2021-Security Misconfiguration",
        "data_exposure": "A02:2021-Cryptographic Failures",
        "misconfiguration": "A05:2021-Security Misconfiguration",
        "cloud_exposure": "A05:2021-Security Misconfiguration",
    }

    def map(self, finding: TriagedFinding) -> str:
        return self.OWASP_MAP.get(finding.category, "A00:Unknown")


class ExploitabilityScorer:
    """Scores how exploitable a finding is (0.0 - 10.0)."""

    def score(self, finding: TriagedFinding) -> float:
        score = 0.0

        # Confidence-based
        score += finding.confidence * 3

        # Tool reliability
        reliable = {"sqlmap": 2.0, "nuclei": 1.8, "dalfox": 1.8, "burp_suite": 2.0}
        score += reliable.get(finding.source_tool, 1.0)

        # Category exploitability
        cat_scores = {
            "sqli": 3.0, "xss": 2.5, "ssrf": 2.5, "auth_flaw": 3.0,
            "jwt_weakness": 2.5, "idor": 2.0, "file_upload": 2.5,
            "cloud_exposure": 3.0, "data_exposure": 2.0, "authz_bypass": 2.5,
        }
        score += cat_scores.get(finding.category, 1.0)

        return min(10.0, score)


class ImpactPredictor:
    """Predicts business impact of a vulnerability (0.0 - 10.0)."""

    def predict(self, finding: TriagedFinding) -> float:
        score = 0.0

        # CVSS-based
        score += finding.cvss_score * 0.5

        # Category impact
        impact_map = {
            "sqli": 4.0, "auth_flaw": 4.0, "jwt_weakness": 3.5,
            "cloud_exposure": 4.0, "data_exposure": 3.5, "authz_bypass": 3.5,
            "ssrf": 3.0, "idor": 3.0, "file_upload": 3.0,
            "xss": 2.0, "open_redirect": 1.5, "misconfiguration": 1.0,
        }
        score += impact_map.get(finding.category, 1.5)

        # URL-based: admin/payment paths score higher
        url = finding.affected_url.lower()
        if any(kw in url for kw in ["/admin", "/payment", "/billing", "/dashboard"]):
            score += 2.0
        if any(kw in url for kw in ["/api/", "/graphql"]):
            score += 1.0

        return min(10.0, score)


class SeverityClassifier:
    """Auto-classifies severity based on all triage data."""

    def classify(self, finding: TriagedFinding) -> str:
        composite = (finding.cvss_score * 0.4 + finding.exploitability_score * 0.3 +
                     finding.impact_score * 0.3)
        if composite >= 9.0:
            return "critical"
        elif composite >= 7.0:
            return "high"
        elif composite >= 4.0:
            return "medium"
        elif composite >= 2.0:
            return "low"
        return "info"
