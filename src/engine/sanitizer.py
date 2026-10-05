"""Sensitive data sanitizer — defense-in-depth for context sent to LLM/Slack/SQLite.

Policy:
- ENV values: NEVER (replace with counts only)
- Secret.data/stringData: NEVER read
- Container command/args: NEVER send
- Logs: ALLOWED but REDACTED + TRIMMED
- Response bodies: ALLOWED but REDACTED
"""
import re

MAX_LOG_LINES = 50
MAX_LOG_LINE_LENGTH = 500

# --- Redaction patterns (order: most specific first) ---

_PEM_RE = re.compile(
    r"-----BEGIN[A-Z \t]+PRIVATE KEY-----[\s\S]*?-----END[A-Z \t]+PRIVATE KEY-----",
    re.MULTILINE,
)

_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Connection strings with credentials
    (re.compile(r"((?:mongodb|postgres|postgresql|mysql|redis|amqp|nats)://)[^\s@]+@", re.IGNORECASE),
     r"\1[REDACTED]@"),
    # Bearer tokens
    (re.compile(r"(Bearer\s+)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    # Authorization: Basic/Token
    (re.compile(r"(Authorization:\s*(?:Basic|Token)\s+)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    # AWS access keys
    (re.compile(r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b"), "[REDACTED_AWS_KEY]"),
    # JWT tokens (three base64url segments separated by dots)
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "[REDACTED_JWT]"),
    # LLM / SaaS provider API keys — these often leak verbatim into
    # SDK exception messages (e.g. OpenAI "Incorrect API key provided:
    # sk-..."). Redacting at sanitizer level keeps them out of Slack
    # posts, stored context, and daily-report summaries regardless of
    # which caller triggers the redaction.
    # OpenAI / Anthropic: "sk-..." (Anthropic uses "sk-ant-...")
    (re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"), "[REDACTED_LLM_KEY]"),
    # Google / Gemini: "AIzaSy..." (39 chars total)
    (re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"), "[REDACTED_GOOGLE_KEY]"),
    # Slack bot/user/app tokens: "xoxb-...", "xoxp-...", "xoxa-...", etc.
    (re.compile(r"\bxox[abpsu]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    # Slack app-level tokens "xapp-..." and rotated tokens "xoxe-...", "xoxe.xapp-..."
    (re.compile(r"\b(?:xoxe\.)?xapp-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\bxoxe-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    # GitHub personal access tokens: "ghp_...", "ghs_...", "github_pat_..."
    (re.compile(r"\b(?:ghp|ghs|gho|ghu|ghr)_[A-Za-z0-9]{20,}\b"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GH_PAT]"),
    # JSON-style secrets: "password": "value" - the quote after the key name keeps
    # the key=value pattern below from matching it. The value may hold escaped quotes (\").
    (re.compile(
        r'(?i)("(?:[A-Za-z0-9_.-]*?)(?:password|passwd|secret|token|api[-_]?key|apikey|'
        r'credentials?|private[-_]?key|access[-_]?key)(?:[A-Za-z0-9_.-]*)"\s*:\s*)"(?:[^"\\]|\\.)*"'),
     r'\1"[REDACTED]"'),
    # Key=value secrets (password, api_key, token, secret, etc.)
    (re.compile(
        r"(?i)((?:password|passwd|api_key|apikey|api[-_]?secret|secret[-_]?key|"
        r"access[-_]?key|private[-_]?key|token|secret|credentials?|"
        r"auth[-_]?token|client[-_]?secret|db[-_]?password|database[-_]?password)"
        r"\s*[=:]\s*)['\"]?(\S+)['\"]?"),
     r"\1[REDACTED]"),
    # Base64 blobs (40+ chars after = or :)
    (re.compile(r"([=:]\s*)[A-Za-z0-9+/]{40,}={0,2}\b"), r"\1[REDACTED_BASE64]"),
    # Hex tokens (32+ hex chars after = or :)
    (re.compile(r"([=:]\s*)[0-9a-fA-F]{32,}\b"), r"\1[REDACTED_HEX]"),
]

# --- Blocked field patterns (stripped entirely from context) ---

_BLOCKED_LINE_RES = [
    re.compile(r"^\s*Env \S+:\s*(secretKeyRef|configMapKeyRef)\(.*$", re.MULTILINE),
    re.compile(r"^\s*EnvFrom:\s*(secretRef|configMapRef)\(.*$", re.MULTILINE),
    re.compile(r"^\s*Command:\s.*$", re.MULTILINE),
    re.compile(r"^\s*Args:\s.*$", re.MULTILINE),
]


def strip_blocked_fields(context: str) -> str:
    """Remove env refs, command, and args lines from context."""
    for pattern in _BLOCKED_LINE_RES:
        context = pattern.sub("", context)
    # Clean up consecutive blank lines left by removals
    context = re.sub(r"\n{3,}", "\n\n", context)
    return context


def redact_logs(text: str) -> str:
    """Regex-based redaction of sensitive patterns + line count/length trim."""
    # Redact PEM blocks first (multi-line)
    text = _PEM_RE.sub("[REDACTED_PEM_KEY]", text)
    # Apply single-line patterns
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    # Trim lines
    lines = text.split("\n")
    trimmed = []
    for line in lines[:MAX_LOG_LINES]:
        if len(line) > MAX_LOG_LINE_LENGTH:
            trimmed.append(line[:MAX_LOG_LINE_LENGTH] + "...[truncated]")
        else:
            trimmed.append(line)
    if len(lines) > MAX_LOG_LINES:
        trimmed.append(f"... [{len(lines) - MAX_LOG_LINES} more lines truncated]")
    return "\n".join(trimmed)


def redact_response_body(body: str, max_chars: int = 500) -> str:
    """Redact sensitive patterns in HTTP response bodies and trim."""
    text = _PEM_RE.sub("[REDACTED_PEM_KEY]", body)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text[:max_chars]


def sanitize_context(context: str) -> str:
    """Main entry: strip blocked fields -> redact logs -> sweep remaining.

    Idempotent — safe to call multiple times.
    """
    if not context:
        return context
    context = strip_blocked_fields(context)
    context = redact_logs(context)
    return context


def sanitize_value(text: str) -> str:
    """Redact sensitive patterns in a single string value."""
    if not text:
        return text
    text = _PEM_RE.sub("[REDACTED_PEM_KEY]", text)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# A dict key that names a secret: its string value is replaced whatever it looks like.
# Only string values - numbers under such keys (e.g. LLM token counts) are not secrets.
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[-_]?key|apikey|credentials?|"
    r"private[-_]?key|access[-_]?key)"
)


def sanitize_dict(data):
    """Recursively sanitize a dict/list structure: string values by pattern, and any
    string under a key that names a secret (password, token, api_key, ...) entirely."""
    if isinstance(data, dict):
        return {
            k: ("[REDACTED]" if isinstance(v, str) and v and isinstance(k, str) and _SENSITIVE_KEY_RE.search(k)
                else sanitize_dict(v))
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [sanitize_dict(item) for item in data]
    elif isinstance(data, str):
        return sanitize_value(data)
    return data


def assert_policy_compliant(text: str) -> list[str]:
    """Return policy violations found in text (for tests).

    Returns empty list if compliant.
    """
    violations = []

    # Check for env refs that should have been stripped
    if re.search(r"secretKeyRef\(", text):
        violations.append("Contains secretKeyRef reference")
    if re.search(r"configMapKeyRef\(", text):
        violations.append("Contains configMapKeyRef reference")
    if re.search(r"secretRef\(", text):
        violations.append("Contains secretRef reference")
    if re.search(r"configMapRef\(", text):
        violations.append("Contains configMapRef reference")

    # Check for command/args
    if re.search(r"^\s*Command:\s", text, re.MULTILINE):
        violations.append("Contains Command field")
    if re.search(r"^\s*Args:\s", text, re.MULTILINE):
        violations.append("Contains Args field")

    # Check for common secret patterns that should have been redacted
    if re.search(r"Bearer\s+(?!(\[REDACTED\]))\S{10,}", text, re.IGNORECASE):
        violations.append("Contains unredacted Bearer token")
    if re.search(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", text):
        violations.append("Contains AWS access key")
    if re.search(r"-----BEGIN[A-Z \t]+PRIVATE KEY-----", text):
        violations.append("Contains PEM private key")

    return violations
