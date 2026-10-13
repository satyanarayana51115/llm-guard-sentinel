import re
from typing import Dict, Any, Tuple
from pydantic import BaseModel, Field, ValidationError

# --- Pydantic Data Contract (Schema Enforcement) ---
class SafeAgentRequest(BaseModel):
    user_id: str = Field(..., min_length=3, description="Valid user identifier")
    role: str = Field(..., pattern="^(standard_user|auditor|admin)$", description="Role-based context")
    query: str = Field(..., min_length=5, max_length=500, description="Input user prompt")

class ToolExecutionSchema(BaseModel):
    action: str = Field(..., pattern="^(read_data|fetch_metrics)$", description="Whitelisted actions only")
    target_id: int = Field(..., ge=1, le=10000, description="Strict numeric boundaries")


# --- Core Guardrail Engine ---
class LLMGuardSentinel:
    """
    Enterprise-grade security gatekeeper for LLMs and autonomous agents.
    Scans for OWASP Top 10 for LLMs vulnerabilities (Prompt Injections, Jailbreaks).
    """

    # Adversarial & Prompt Injection Signature Patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
        r"system\s*prompt\s*override",
        r"bypass\s+safety\s+filter",
        r"act\s+as\s+dan",
        r"drop\s+database",
        r"delete\s+from",
        r"dump\s+all\s+records",
        r"show\s+secret\s+key",
        r"expose\s+internal\s+tokens"
    ]

    @classmethod
    def scan_ingress_prompt(cls, prompt: str) -> Tuple[bool, str]:
        """
        Inspects incoming prompt against known adversarial jailbreaks and injections.
        Returns: (is_safe: bool, reason: str)
        """
        normalized_prompt = prompt.lower().strip()

        for pattern in cls.INJECTION_PATTERNS:
            if re.search(pattern, normalized_prompt):
                return False, f"Ingress Breach: Detected adversarial pattern matching '{pattern}'"

        return True, "Passed Ingress Safety Gate"

    @classmethod
    def validate_tool_intent(cls, tool_call: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Deterministic barrier ensuring LLM cannot invoke unapproved tools
        or inject malformed payloads into underlying infrastructure.
        """
        try:
            validated = ToolExecutionSchema(**tool_call)
            return True, validated.model_dump()
        except ValidationError as e:
            error_details = e.errors()[0]["msg"]
            return False, {"error": f"Tool Execution Blocked: {error_details}"}