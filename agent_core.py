import logging
from typing import Dict, Any
from guardrails import LLMGuardSentinel, SafeAgentRequest

# Configure Security Audit Logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")
logger = logging.getLogger("SentinelAgent")

class SecureAgentRuntime:
    """
    State-driven agent runtime that mandates deterministic security barriers 
    before probabilistic execution.
    """

    def __init__(self, agent_name: str = "Enterprise-Sentinel-v1"):
        self.agent_name = agent_name

    def process_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes request lifecycle through the security gatekeeper.
        """
        # Step 1: Pydantic Data Contract Validation
        try:
            validated_req = SafeAgentRequest(**payload)
        except Exception as e:
            logger.warning(f"Schema Violation: Malformed payload rejected: {str(e)}")
            return {"status": "REJECTED", "reason": "Schema validation failed", "details": str(e)}

        # Step 2: Ingress Adversarial Inspection
        is_safe, reason = LLMGuardSentinel.scan_ingress_prompt(validated_req.query)
        if not is_safe:
            logger.error(f"SECURITY BREACH ATTEMPT: User '{validated_req.user_id}' triggered -> {reason}")
            return {
                "status": "BLOCKED",
                "reason": "Security Boundary Violation",
                "audit_flag": reason
            }

        # Step 3: Safe Deterministic Execution
        logger.info(f"Payload cleared ingress gate for user '{validated_req.user_id}'. Executing intent.")
        return {
            "status": "SUCCESS",
            "agent": self.agent_name,
            "response": f"Processed query safely: '{validated_req.query}'"
        }

    def execute_tool_safely(self, raw_tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates LLM-generated tool arguments against strict deterministic boundary rules.
        """
        is_valid, validated_data_or_err = LLMGuardSentinel.validate_tool_intent(raw_tool_call)
        if not is_valid:
            logger.error(f"TOOL BARRIER INTERCEPT: Blocked malicious or malformed tool call: {validated_data_or_err}")
            return {"status": "BLOCKED", "error": validated_data_or_err}

        logger.info(f"Tool execution authorized for action '{validated_data_or_err['action']}'.")
        return {"status": "EXECUTED", "data": validated_data_or_err}