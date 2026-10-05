"""Guardian tests for src.engine.sanitizer — sensitive data must never leak."""
import unittest

from src.engine.sanitizer import (
    sanitize_context,
    sanitize_dict,
    sanitize_value,
    redact_logs,
    redact_response_body,
    strip_blocked_fields,
    assert_policy_compliant,
    MAX_LOG_LINES,
    MAX_LOG_LINE_LENGTH,
)


class TestBlockedFields(unittest.TestCase):
    """Env refs, Command, and Args must be stripped entirely."""

    def test_secret_key_ref_stripped(self):
        text = "Container app: running\n  Env DB_PASS: secretKeyRef(my-secret/password)\n  Image: nginx"
        result = strip_blocked_fields(text)
        self.assertNotIn("secretKeyRef", result)
        self.assertNotIn("DB_PASS", result)
        self.assertIn("Image: nginx", result)

    def test_config_map_key_ref_stripped(self):
        text = "  Env APP_URL: configMapKeyRef(my-config/url)"
        result = strip_blocked_fields(text)
        self.assertNotIn("configMapKeyRef", result)

    def test_secret_ref_stripped(self):
        text = "  EnvFrom: secretRef(my-secret)"
        result = strip_blocked_fields(text)
        self.assertNotIn("secretRef", result)

    def test_config_map_ref_stripped(self):
        text = "  EnvFrom: configMapRef(my-config)"
        result = strip_blocked_fields(text)
        self.assertNotIn("configMapRef", result)

    def test_command_stripped(self):
        text = "Container app: running\n  Command: ['/bin/sh', '-c', 'echo secret']\n  Image: nginx"
        result = strip_blocked_fields(text)
        self.assertNotIn("Command:", result)
        self.assertNotIn("echo secret", result)
        self.assertIn("Image: nginx", result)

    def test_args_stripped(self):
        text = "  Args: ['--password=secret123', '--verbose']"
        result = strip_blocked_fields(text)
        self.assertNotIn("Args:", result)
        self.assertNotIn("password=secret123", result)

    def test_safe_content_preserved(self):
        text = (
            "## Pod: default/my-app\n"
            "Phase: Running\n"
            "Container app: running, restarts=0\n"
            "  Image: nginx:1.25\n"
            "  Resources: requests={'cpu': '100m'}, limits={'cpu': '500m'}\n"
        )
        result = strip_blocked_fields(text)
        self.assertEqual(text.strip(), result.strip())


class TestLogRedaction(unittest.TestCase):
    """Sensitive patterns in logs must be redacted; safe content preserved."""

    def test_bearer_token(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
        result = redact_logs(text)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", result)
        self.assertIn("[REDACTED]", result)

    def test_password_equals(self):
        result = redact_logs("DB_PASSWORD=mysupersecretpassword")
        self.assertNotIn("mysupersecretpassword", result)
        self.assertIn("[REDACTED]", result)

    def test_password_colon(self):
        result = redact_logs("password: 'hunter2'")
        self.assertNotIn("hunter2", result)

    def test_connection_string_postgres(self):
        result = redact_logs("postgres://admin:s3cret@db.example.com:5432/mydb")
        self.assertNotIn("s3cret", result)
        self.assertNotIn("admin", result)
        self.assertIn("@db.example.com", result)

    def test_connection_string_mongodb(self):
        result = redact_logs("mongodb://user:pass@mongo.svc:27017/db")
        self.assertNotIn("pass", result)
        self.assertIn("@mongo.svc", result)

    def test_connection_string_redis(self):
        result = redact_logs("redis://default:mytoken@redis.svc:6379")
        self.assertNotIn("mytoken", result)

    def test_aws_access_key(self):
        result = redact_logs("aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result)
        self.assertIn("[REDACTED_AWS_KEY]", result)

    def test_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        # JWT in a non-key context is caught by JWT pattern
        result = redact_logs(f"header: {jwt}")
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", result)
        self.assertIn("[REDACTED_JWT]", result)
        # JWT after token= is caught by key-value pattern (still redacted)
        result2 = redact_logs(f"token={jwt}")
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", result2)
        self.assertIn("[REDACTED]", result2)

    def test_openai_api_key(self):
        """`sk-...` tokens leaked bare (no `key=` prefix) in exception
        messages — redacted via the provider-token pattern."""
        key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
        result = redact_logs(f"Incorrect API key provided: {key}")
        self.assertNotIn(key, result)
        self.assertIn("[REDACTED_LLM_KEY]", result)

    def test_anthropic_api_key(self):
        key = "sk-ant-api03-" + "a" * 40
        result = redact_logs(f"Invalid API key: {key}")
        self.assertNotIn(key, result)
        self.assertIn("[REDACTED_LLM_KEY]", result)

    def test_google_api_key(self):
        key = "AIza" + "a" * 35
        result = redact_logs(f"Using credentials {key} failed")
        self.assertNotIn(key, result)
        self.assertIn("[REDACTED_GOOGLE_KEY]", result)

    def test_slack_bot_token(self):
        # built from parts so that secret scanners do not flag the test itself
        token = "xox" + "b-" + "1234567890-1234567890-" + "abcdefghijklmnopqrstuvwx"
        result = redact_logs(f"slack auth error for {token}")
        self.assertNotIn(token, result)
        self.assertIn("[REDACTED_SLACK_TOKEN]", result)

    def test_slack_app_token(self):
        token = "xa" + "pp-1-" + "A0123456789-1234567890123-" + "abcdef0123456789"
        result = redact_logs(f"socket mode failed with {token}")
        self.assertNotIn(token, result)
        self.assertIn("[REDACTED_SLACK_TOKEN]", result)

    def test_slack_rotated_app_token(self):
        token = "xo" + "xe.xapp-1-" + "A0123456789-1234567890123-" + "abcdef0123456789"
        result = redact_logs(f"refresh returned {token}")
        self.assertNotIn(token, result)
        self.assertNotIn("xapp-1-A0123456789", result)
        self.assertIn("[REDACTED_SLACK_TOKEN]", result)

    def test_github_pat(self):
        pat = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        result = redact_logs(f"git push failed: token {pat} rejected")
        self.assertNotIn(pat, result)
        self.assertIn("[REDACTED_GH_TOKEN]", result)

    def test_github_fine_grained_pat(self):
        pat = "github_pat_" + "A1b2C3d4E5" * 3
        result = redact_logs(f"token {pat}")
        self.assertNotIn(pat, result)


    def test_pem_key(self):
        text = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----"
        result = redact_logs(text)
        self.assertNotIn("MIIEvQIBADANBg", result)
        self.assertIn("[REDACTED_PEM_KEY]", result)

    def test_base64_blob(self):
        b64 = "A" * 50
        result = redact_logs(f"secret_data={b64}")
        self.assertNotIn(b64, result)

    def test_hex_token(self):
        hextoken = "a1b2c3d4e5f6" * 6  # 72 hex chars
        result = redact_logs(f"session_id={hextoken}")
        self.assertNotIn(hextoken, result)

    def test_safe_log_preserved(self):
        text = "2024-01-15T10:30:00Z INFO Server started on port 8080"
        result = redact_logs(text)
        self.assertEqual(text, result)

    def test_error_messages_preserved(self):
        text = "ERROR: Connection refused to database on port 5432"
        result = redact_logs(text)
        self.assertEqual(text, result)

    def test_line_count_trimmed(self):
        lines = [f"log line {i}" for i in range(100)]
        text = "\n".join(lines)
        result = redact_logs(text)
        result_lines = result.split("\n")
        self.assertEqual(len(result_lines), MAX_LOG_LINES + 1)  # +1 for truncation message
        self.assertIn("more lines truncated", result_lines[-1])

    def test_long_line_trimmed(self):
        long_line = "A" * 1000
        result = redact_logs(long_line)
        self.assertLessEqual(len(result.split("\n")[0]), MAX_LOG_LINE_LENGTH + 20)  # +overhead for suffix
        self.assertIn("[truncated]", result)


class TestResponseBodyRedaction(unittest.TestCase):
    """Tokens in HTTP response bodies must be redacted."""

    def test_json_with_token(self):
        body = '{"access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc", "type": "bearer"}'
        result = redact_response_body(body)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", result)

    def test_password_in_error(self):
        body = "Error: authentication failed for password=secret123"
        result = redact_response_body(body)
        self.assertNotIn("secret123", result)

    def test_body_trimmed_to_max(self):
        body = "x" * 1000
        result = redact_response_body(body, max_chars=500)
        self.assertLessEqual(len(result), 500)

    def test_safe_body_preserved(self):
        body = '{"status": "ok", "code": 200}'
        result = redact_response_body(body)
        self.assertEqual(body, result)


class TestSanitizeContextEndToEnd(unittest.TestCase):
    """Realistic full pod context with multiple secrets -> all sanitized."""

    REALISTIC_CONTEXT = """\
## Pod: production/my-app-7f8d9b6c4-xk2lm
Phase: Running
Node: worker-01
Container app: running, restarts=5
  Detail: exit code 1
  Image: registry.example.com/my-app:v2.3.1
  Command: ['node', 'server.js', '--db-pass=secret123']
  Args: ['--token=abc123def']
  Resources: requests={'cpu': '100m', 'memory': '256Mi'}, limits={'cpu': '500m', 'memory': '512Mi'}
  VolumeMount: config -> /app/config
  Env DB_PASSWORD: secretKeyRef(my-secret/db-password)
  Env API_KEY: secretKeyRef(api-secrets/key)
  Env CONFIG_URL: configMapKeyRef(app-config/base-url)
  EnvFrom: secretRef(env-secrets)
  EnvFrom: configMapRef(app-env)

## Pod Logs (last 50 lines)
```
2024-01-15T10:30:00Z Connecting to postgres://admin:s3cretP4ss@db.prod.svc:5432/mydb
2024-01-15T10:30:01Z Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature
2024-01-15T10:30:02Z AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
2024-01-15T10:30:03Z INFO: Server ready on port 8080
2024-01-15T10:30:04Z -----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj
-----END PRIVATE KEY-----
```

## Events
  [Warning] 2024-01-15T10:29:00Z - BackOff: restarting failed container
"""

    def test_all_secrets_redacted(self):
        result = sanitize_context(self.REALISTIC_CONTEXT)
        # Secret values must not appear
        self.assertNotIn("s3cretP4ss", result)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result)
        self.assertNotIn("MIIEvQIBADANBg", result)
        self.assertNotIn("secret123", result)
        self.assertNotIn("abc123def", result)
        # Env refs must be stripped
        self.assertNotIn("secretKeyRef", result)
        self.assertNotIn("configMapKeyRef", result)
        self.assertNotIn("secretRef", result)
        self.assertNotIn("configMapRef", result)
        # Command/Args must be stripped
        self.assertNotIn("Command:", result)
        self.assertNotIn("Args:", result)

    def test_diagnostic_value_preserved(self):
        result = sanitize_context(self.REALISTIC_CONTEXT)
        # Diagnostic info must survive
        self.assertIn("production/my-app", result)
        self.assertIn("Phase: Running", result)
        self.assertIn("restarts=5", result)
        self.assertIn("Image: registry.example.com/my-app:v2.3.1", result)
        self.assertIn("Resources:", result)
        self.assertIn("BackOff", result)
        self.assertIn("Server ready on port 8080", result)

    def test_idempotent(self):
        result1 = sanitize_context(self.REALISTIC_CONTEXT)
        result2 = sanitize_context(result1)
        self.assertEqual(result1, result2)

    def test_empty_context(self):
        self.assertEqual(sanitize_context(""), "")
        self.assertEqual(sanitize_context(None), None)


class TestPolicyGuardian(unittest.TestCase):
    """assert_policy_compliant catches violations; clean context passes."""

    def test_catches_secret_key_ref(self):
        violations = assert_policy_compliant("  Env DB: secretKeyRef(secret/key)")
        self.assertTrue(any("secretKeyRef" in v for v in violations))

    def test_catches_command(self):
        violations = assert_policy_compliant("  Command: ['node', 'app.js']")
        self.assertTrue(any("Command" in v for v in violations))

    def test_catches_args(self):
        violations = assert_policy_compliant("  Args: ['--verbose']")
        self.assertTrue(any("Args" in v for v in violations))

    def test_catches_bearer_token(self):
        violations = assert_policy_compliant("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9long_enough_token")
        self.assertTrue(any("Bearer" in v for v in violations))

    def test_catches_aws_key(self):
        violations = assert_policy_compliant("key=AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(any("AWS" in v for v in violations))

    def test_catches_pem_key(self):
        violations = assert_policy_compliant("-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----")
        self.assertTrue(any("PEM" in v for v in violations))

    def test_clean_context_passes(self):
        clean = (
            "## Pod: default/my-app\n"
            "Phase: Running\n"
            "Container app: running, restarts=0\n"
            "  Image: nginx:1.25\n"
            "  Resources: requests={'cpu': '100m'}\n"
            "Node Ready: True\n"
        )
        violations = assert_policy_compliant(clean)
        self.assertEqual(violations, [])


class TestCollectorOutputCompliance(unittest.TestCase):
    """Simulated raw collector output -> sanitize -> assert_policy_compliant returns no violations."""

    def test_raw_collector_output_sanitized(self):
        raw = """\
## Pod: staging/api-server-abc123
Phase: CrashLoopBackOff
Container api: waiting (CrashLoopBackOff), restarts=12
  Image: myregistry/api:v1.5
  Command: ['python', 'manage.py', 'runserver']
  Args: ['--settings=prod']
  Resources: requests={'cpu': '200m'}, limits={'cpu': '1'}
  Env DATABASE_URL: secretKeyRef(db-creds/url)
  Env REDIS_PASSWORD: secretKeyRef(redis-secret/password)
  Env APP_CONFIG: configMapKeyRef(app-config/settings)
  EnvFrom: secretRef(api-secrets)

## Pod Logs (last 50 lines)
```
2024-01-15 Connecting to postgres://user:password123@db:5432/app
2024-01-15 token=AKIAIOSFODNN7EXAMPLE
2024-01-15 ERROR: connection refused
```
"""
        sanitized = sanitize_context(raw)
        violations = assert_policy_compliant(sanitized)
        self.assertEqual(violations, [], f"Policy violations found: {violations}")
        # Verify diagnostic data survived
        self.assertIn("staging/api-server-abc123", sanitized)
        self.assertIn("CrashLoopBackOff", sanitized)
        self.assertIn("restarts=12", sanitized)
        self.assertIn("connection refused", sanitized)


class TestSanitizeDict(unittest.TestCase):
    """sanitize_dict recursively redacts sensitive string values in dicts/lists."""

    def test_redacts_password_in_dict(self):
        data = {"log": "password=secret123", "count": 5}
        result = sanitize_dict(data)
        self.assertNotIn("secret123", result["log"])
        self.assertIn("[REDACTED]", result["log"])
        self.assertEqual(result["count"], 5)

    def test_redacts_in_nested_list(self):
        data = {
            "logs": [
                "INFO: starting",
                "postgres://admin:s3cret@db:5432/mydb",
                "FATAL: shutdown",
            ]
        }
        result = sanitize_dict(data)
        self.assertNotIn("s3cret", result["logs"][1])
        self.assertNotIn("admin", result["logs"][1])
        self.assertEqual(result["logs"][0], "INFO: starting")
        self.assertEqual(result["logs"][2], "FATAL: shutdown")

    def test_redacts_jwt_in_nested_dict(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        data = {"diagnostics": {"message": f"token: {jwt}"}}
        result = sanitize_dict(data)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", result["diagnostics"]["message"])

    def test_preserves_non_string_values(self):
        data = {"restarts": 5, "ready": True, "phase": "Running", "metrics": None}
        result = sanitize_dict(data)
        self.assertEqual(result["restarts"], 5)
        self.assertEqual(result["ready"], True)
        self.assertEqual(result["phase"], "Running")
        self.assertIsNone(result["metrics"])

    def test_handles_empty_dict(self):
        self.assertEqual(sanitize_dict({}), {})

    def test_handles_empty_list(self):
        self.assertEqual(sanitize_dict([]), [])

    def test_deeply_nested(self):
        data = {"a": {"b": {"c": [{"d": "password=hunter2"}]}}}
        result = sanitize_dict(data)
        self.assertNotIn("hunter2", result["a"]["b"]["c"][0]["d"])

    def test_pem_in_event_message(self):
        data = {
            "events": [
                {"reason": "Error", "message": "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----"}
            ]
        }
        result = sanitize_dict(data)
        self.assertNotIn("ABC", result["events"][0]["message"])
        self.assertIn("[REDACTED_PEM_KEY]", result["events"][0]["message"])


class TestSanitizeValue(unittest.TestCase):
    """sanitize_value redacts individual strings."""

    def test_password(self):
        result = sanitize_value("api_key=mysecret123")
        self.assertNotIn("mysecret123", result)

    def test_safe_string(self):
        self.assertEqual(sanitize_value("INFO: all good"), "INFO: all good")

    def test_empty_string(self):
        self.assertEqual(sanitize_value(""), "")

    def test_none(self):
        self.assertIsNone(sanitize_value(None))


if __name__ == "__main__":
    unittest.main()
