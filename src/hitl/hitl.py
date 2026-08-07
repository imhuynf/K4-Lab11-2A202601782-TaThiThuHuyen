"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 11: Confidence Router
  TODO 12: Design 3 HITL decision points
"""
from dataclasses import dataclass
import math


# ============================================================
# TODO 11: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(confidence)
            or not 0.0 <= confidence <= 1.0
        ):
            raise ValueError("confidence must be a finite number between 0.0 and 1.0")

        normalized_action = str(action_type).strip().casefold()
        if normalized_action in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {normalized_action}",
                priority="high",
                requires_human=True,
            )

        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )

        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )

        return RoutingDecision(
            action="escalate",
            confidence=confidence,
            reason="Low confidence — escalating",
            priority="high",
            requires_human=True,
        )


# ============================================================
# TODO 12: Design 3 HITL decision points + a review lifecycle
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
# - approval_path: What approve/reject/timeout decision is recorded?
# - audit_fields: Which correlation ID, intent and proposed action/diff are logged?
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "High-value transfer approval",
        "trigger": (
            "Any transfer_money action, or a transfer above the customer's "
            "configured risk threshold, regardless of model confidence."
        ),
        "hitl_model": "human-in-the-loop",
        "context_needed": (
            "Verified customer identity, source and destination accounts, amount, "
            "currency, fraud signals, beneficiary history, and the exact proposed transaction diff."
        ),
        "example": "A customer asks the agent to transfer 50,000,000 VND to a new beneficiary.",
        "approval_path": (
            "Approve creates a signed approval ID and permits one exact transaction; "
            "reject cancels it; timeout after 10 minutes fails closed and requires a new request."
        ),
        "audit_fields": (
            "request_id, correlation_id, user_id, intent, source_account, destination, "
            "amount, proposed_diff, risk_signals, reviewer_id, decision, approval_id, timestamp"
        ),
    },
    {
        "id": 2,
        "name": "Account and identity change review",
        "trigger": (
            "close_account, change_password, delete_data, or update_personal_info; "
            "also any identity mismatch or account-takeover signal."
        ),
        "hitl_model": "human-in-the-loop",
        "context_needed": (
            "Authentication evidence, recent login/device history, current values, proposed changes, "
            "customer confirmation channel, and policy checks."
        ),
        "example": "A newly seen device requests both a phone-number change and password reset.",
        "approval_path": (
            "Approve authorizes only the displayed field-level diff; reject preserves current data "
            "and alerts the customer; timeout fails closed and opens a fraud-review case."
        ),
        "audit_fields": (
            "request_id, correlation_id, user_id, intent, before_state_hash, proposed_diff, "
            "device_risk, reviewer_id, decision, approval_id, timeout_reason, timestamp"
        ),
    },
    {
        "id": 3,
        "name": "Ambiguous or policy-sensitive response",
        "trigger": (
            "Confidence from 0.7 to below 0.9, conflicting retrieval evidence, or a response "
            "that the safety and accuracy judges disagree on."
        ),
        "hitl_model": "human-as-tiebreaker",
        "context_needed": (
            "User question, draft response, cited sources and timestamps, confidence, guardrail findings, "
            "ground-truth comparison, and a highlighted response diff."
        ),
        "example": "Two sources disagree about the current 12-month savings interest rate.",
        "approval_path": (
            "Approve releases the reviewed text; edit records and releases the reviewer revision; "
            "reject returns a safe fallback; timeout returns no unverified factual claim."
        ),
        "audit_fields": (
            "request_id, correlation_id, user_id, intent, model_response, source_ids, confidence, "
            "judge_scores, proposed_diff, reviewer_id, decision, final_response_hash, timestamp"
        ),
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
