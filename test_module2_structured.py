from enum import Enum
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

load_dotenv()
client = genai.Client()


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Schema extinsa Pydantic
class LogAnalysis(BaseModel):
    severity: SeverityLevel = Field(
        description="The incident severity level: LOW, MEDIUM, HIGH, or CRITICAL."
    )
    error_code: int = Field(
        description="HTTP or system error code found in log, or -1 if none."
    )
    is_compromised: bool = Field(
        description="True if unauthorized access succeeded or PAM/auth was bypassed."
    )
    summary: str = Field(
        description="One-sentence technical summary of the security event."
    )
    recommended_fix: list[str] = Field(
        description="List of concrete remediation steps to fix the vulnerability."
    )


SYSTEM_PROMPT = """You are an expert SIEM log analysis engine.
Parse raw server logs into a strictly validated JSON structure according to the provided schema.
Accurately identify severity, error codes, whether the system was compromised, and concrete fixes."""


def parse_server_log(raw_log: str) -> LogAnalysis:
    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=f"Analyze the following raw server log:\n{raw_log}",
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=LogAnalysis,
        ),
    )
    # Validare si deserializare directa din JSON in obiect Pydantic
    return LogAnalysis.model_validate_json(response.text)


if __name__ == "__main__":
    sample = (
        "2026-10-15 02:11:44 [ALERT] sshd[9012]: Accepted password for root "
        "from 198.51.100.77 port 44122 ssh2 (ErrorCode=401 bypassed via PAM bug)"
    )
    parsed = parse_server_log(sample)
    print("Parsed JSON Output:\n", parsed.model_dump_json(indent=2))


# --- Unit Test automat (Rulat de pytest) ---
def test_ssh_breach_log_parsing():
    sample_log = (
        "2026-10-15 02:11:44 [ALERT] sshd[9012]: Accepted password for root "
        "from 198.51.100.77 port 44122 ssh2 (ErrorCode=401 bypassed via PAM bug)"
    )
    result = parse_server_log(sample_log)

    assert result.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    assert result.error_code == 401
    assert result.is_compromised is True
    assert len(result.recommended_fix) >= 1