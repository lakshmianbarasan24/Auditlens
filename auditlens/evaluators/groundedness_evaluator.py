from typing import List
from auditlens.schemas.models import ExchangeItem, Finding, SeverityLevel, AppProfile

class GroundednessEvaluator:
    """
    Evaluates RAG Faithfulness / Groundedness against retrieved source context.
    Computes precision & claim validation score.
    Mapped Control: AI Quality Gate (RAGAS / DeepEval Faithfulness).
    """
    def __init__(self, threshold: float = 0.85):
        self.threshold = threshold

    def run(self, profile: AppProfile, exchanges: List[ExchangeItem]) -> List[Finding]:
        findings = []

        total_faithfulness = 0.0
        evaluated_count = 0

        for ex in exchanges:
            if ex.retrieved_chunks:
                evaluated_count += 1
                # Simplified deterministic RAGAS Faithfulness evaluation metric simulation:
                # Compare terms in response text against context terms
                context_text = " ".join([c.get("content", "") or c.get("text", "") for c in ex.retrieved_chunks]).lower()
                resp_text = ex.response_text.lower()

                # If response contains claims not grounded in retrieved context
                words_in_resp = [w for w in resp_text.split() if len(w) > 4]
                if not words_in_resp:
                    faithfulness = 1.0
                else:
                    grounded_words = [w for w in words_in_resp if w in context_text]
                    faithfulness = len(grounded_words) / len(words_in_resp)

                # Check explicitly set metadata faithfulness if provided in dataset
                if ex.user_metadata and "faithfulness_score" in ex.user_metadata:
                    faithfulness = float(ex.user_metadata["faithfulness_score"])

                total_faithfulness += faithfulness

        if evaluated_count > 0:
            avg_faithfulness = total_faithfulness / evaluated_count
            if avg_faithfulness < self.threshold:
                findings.append(
                    Finding(
                        finding_id="ragas-groundedness-failure",
                        test_id="groundedness_faithfulness",
                        title="AI Quality Gate: Groundedness / Faithfulness below threshold",
                        severity=SeverityLevel.MEDIUM,
                        description=f"RAGAS Faithfulness score averaged {avg_faithfulness:.2f}, failing the required quality threshold of {self.threshold:.2f}.",
                        control_mapped="Quality Gate (RAGAS Faithfulness)",
                        evidence_cited=f"Evaluated {evaluated_count} RAG Q&A flows. Average faithfulness = {avg_faithfulness:.2f} (Threshold: {self.threshold})",
                        exchange_id=exchanges[0].exchange_id if exchanges else None,
                        suggested_fix="Tune retrieval top-k, implement hallucination filter guardrails, or upgrade system prompt groundedness instructions."
                    )
                )

        return findings
