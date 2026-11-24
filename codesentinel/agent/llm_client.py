import json
import re
from typing import Dict, Any, Optional
import httpx
from codesentinel.core.config import settings
from codesentinel.core.logger import logger
from codesentinel.agent.prompts import AUDIT_SYSTEM_PROMPT


class LLMClient:
    """Unified client for OpenAI, Groq, Ollama, and Mock LLM providers."""

    def __init__(
        self,
        provider: str = settings.LLM_PROVIDER,
        api_key: str = settings.LLM_API_KEY,
        model: str = settings.LLM_MODEL,
        base_url: str = settings.LLM_BASE_URL,
    ):
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    def generate_fix(self, prompt: str) -> Dict[str, Any]:
        """Queries the LLM and returns parsed structured JSON remediation."""
        if self.provider == "mock":
            return self._mock_remediation(prompt)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": settings.LLM_TEMPERATURE,
            "response_format": {"type": "json_object"} if self.provider in ("openai", "groq") else None
        }

        url = f"{self.base_url}/chat/completions"

        try:
            with httpx.Client(timeout=45.0) as client:
                resp = client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return self._parse_json(content)
        except Exception as e:
            logger.warning(f"LLM API request failed: {e}. Falling back to heuristic rule-based remediator.")
            return self._mock_remediation(prompt)

    @staticmethod
    def _parse_json(raw_text: str) -> Dict[str, Any]:
        """Robustly extracts JSON from model output."""
        cleaned = raw_text.strip()
        # Remove markdown codeblocks if present
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Fallback regex extraction of JSON object
            match = re.search(r"(\{.*\})", cleaned, re.DOTALL)
            if match:
                return json.loads(match.group(1))
            raise ValueError(f"Could not parse valid JSON from LLM response: {raw_text[:200]}")

    @staticmethod
    def _mock_remediation(prompt: str) -> Dict[str, Any]:
        """
        Deterministic offline remediator used for testing, CI/CD, and demo runs
        without requiring live API tokens.
        """
        if "SQL" in prompt or "cursor.execute" in prompt:
            return {
                "explanation": "Parametrized SQL query using tuple arguments instead of f-string interpolation to prevent SQL injection (CWE-89).",
                "original_snippet": 'cursor.execute(f"SELECT * FROM users WHERE username = \'{username}\'")',
                "remediated_snippet": 'cursor.execute("SELECT * FROM users WHERE username = %s", (username,))'
            }
        elif "eval(" in prompt:
            return {
                "explanation": "Replaced insecure eval() call with ast.literal_eval to safely parse literals without executing arbitrary code.",
                "original_snippet": "data = eval(raw_input_data)",
                "remediated_snippet": "import ast\n    data = ast.literal_eval(raw_input_data)"
            }
        elif "shell=True" in prompt or "os.system" in prompt:
            return {
                "explanation": "Removed shell=True and passed arguments as a list to avoid OS command injection (CWE-78).",
                "original_snippet": 'subprocess.run(f"cat {filename}", shell=True)',
                "remediated_snippet": 'subprocess.run(["cat", filename], shell=False, check=True)'
            }
        else:
            return {
                "explanation": "Applied automated null-check and sanitized input parameters to resolve test failure.",
                "original_snippet": "return self.data[key]",
                "remediated_snippet": "return self.data.get(key, None)"
            }
