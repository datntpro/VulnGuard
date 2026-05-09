"""
Secret Detection Scanners:
- Gitleaks: Git history + filesystem (binary, fast)
- DetectSecretsScanner: dùng Python API trực tiếp (bypass CLI filter bug)
"""
import json
import os
from typing import List, Dict, Any

from scanner.scanners.base import BaseScanner, run_command, make_fingerprint


class GitleaksScanner(BaseScanner):
    """Gitleaks — Scan hardcoded secrets, API keys, credentials."""
    scan_type = "SECRETS"
    tool_name = "gitleaks"

    async def scan(self) -> List[Dict[str, Any]]:
        findings = []

        cmd = [
            "gitleaks",
            "detect",
            "--source", self.scan_path,
            "--report-format", "json",
            "--report-path", "/tmp/gitleaks-report.json",
            "--no-git",
            "--exit-code=0",   # Không fail khi tìm thấy secret (Gitleaks v8)
            "--redact",        # Che giá trị secret trong output
            "--quiet",
        ]

        rc, stdout, stderr = await run_command(cmd, timeout=120)

        # Đọc report file
        try:
            if os.path.exists("/tmp/gitleaks-report.json"):
                with open("/tmp/gitleaks-report.json", "r") as f:
                    content = f.read().strip()
                if content and content != "null":
                    results = json.loads(content)
                else:
                    results = []
            else:
                results = []
        except Exception:
            results = []

        for result in (results or []):
            rule_id = result.get("RuleID", "")
            description = result.get("Description", "")
            file_path = result.get("File", "")
            line = result.get("StartLine", 0)
            match = result.get("Match", "")
            commit = result.get("Commit", "")

            findings.append({
                "tool": "gitleaks",
                "scan_type": "SECRETS",
                "rule_id": rule_id,
                "title": f"[Secret] {description or rule_id}",
                "description": (
                    f"Phát hiện secret/credential trong file.\n"
                    f"Rule: {rule_id}\n"
                    f"Match: {match[:100] if match else 'N/A'}\n"
                    f"Commit: {commit[:12] if commit else 'filesystem'}"
                ),
                "severity": "CRITICAL",
                "file_path": file_path.replace(self.scan_path, "").lstrip("/"),
                "line_start": line,
                "code_snippet": match[:200] if match else "",
                "fingerprint": make_fingerprint("gitleaks", rule_id, file_path, line, description),
                "raw": result,
            })

        return findings


class DetectSecretsScanner(BaseScanner):
    """detect-secrets — Dùng Python API trực tiếp để tránh CLI filter bug.

    Bug: detect-secrets CLI v1.5+ mặc định bật filter
    `is_ignored_due_to_verification_policies` (min_level=2) khiến
    tất cả unverified secrets bị lọc bỏ.

    Fix: dùng Python API với transient_settings, chỉ giữ lại các
    heuristic filters cần thiết, bỏ verification filter.
    """
    scan_type = "SECRETS"
    tool_name = "detect-secrets"

    # Settings override — bỏ verification filter, giữ các filter heuristic an toàn
    SAFE_SETTINGS = {
        "plugins_used": [
            {"name": "AWSKeyDetector"},
            {"name": "AzureStorageKeyDetector"},
            {"name": "BasicAuthDetector"},
            {"name": "CloudantDetector"},
            {"name": "DiscordBotTokenDetector"},
            {"name": "GitHubTokenDetector"},
            {"name": "GitLabTokenDetector"},
            {"name": "HexHighEntropyString", "limit": 3.0},
            {"name": "Base64HighEntropyString", "limit": 4.5},
            {"name": "IbmCloudIamDetector"},
            {"name": "JwtTokenDetector"},
            {"name": "KeywordDetector", "keyword_exclude": ""},
            {"name": "MailchimpDetector"},
            {"name": "NpmDetector"},
            {"name": "OpenAIDetector"},
            {"name": "PrivateKeyDetector"},
            {"name": "SendGridDetector"},
            {"name": "SlackDetector"},
            {"name": "StripeDetector"},
            {"name": "TwilioKeyDetector"},
        ],
        "filters_used": [
            # Chỉ giữ các filter an toàn, BỎ is_ignored_due_to_verification_policies
            {"path": "detect_secrets.filters.allowlist.is_line_allowlisted"},
            {"path": "detect_secrets.filters.heuristic.is_lock_file"},
            {"path": "detect_secrets.filters.heuristic.is_not_alphanumeric_string"},
            {"path": "detect_secrets.filters.heuristic.is_potential_uuid"},
            {"path": "detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign"},
            {"path": "detect_secrets.filters.heuristic.is_swagger_file"},
            {"path": "detect_secrets.filters.heuristic.is_templated_secret"},
        ],
    }

    # File extensions cần scan
    SCAN_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".rb", ".php", ".cs",
        ".env", ".env.example", ".env.local",
        ".yaml", ".yml", ".json", ".toml", ".ini",
        ".cfg", ".conf", ".config", ".properties",
        ".sh", ".bash", ".zsh",
        ".tf", ".tfvars",
        ".xml", ".gradle",
        "Dockerfile",
    }

    async def scan(self) -> List[Dict[str, Any]]:
        try:
            from detect_secrets import SecretsCollection
            from detect_secrets.settings import transient_settings
        except ImportError:
            return []

        findings = []

        # Thu thập tất cả files cần scan
        files_to_scan = self._collect_files()
        if not files_to_scan:
            return []

        try:
            with transient_settings(self.SAFE_SETTINGS):
                secrets_collection = SecretsCollection()
                for file_path in files_to_scan:
                    try:
                        secrets_collection.scan_file(file_path)
                    except Exception:
                        continue

            for filename, secret_set in secrets_collection.data.items():
                for secret in secret_set:
                    secret_type = secret.type
                    line_num = secret.line_number
                    is_verified = getattr(secret, "is_verified", False)

                    findings.append({
                        "tool": "detect-secrets",
                        "scan_type": "SECRETS",
                        "rule_id": secret_type,
                        "title": f"[Secret] {secret_type}",
                        "description": (
                            f"Possible {secret_type} detected in file.\n"
                            f"Verified: {'YES — Confirmed real secret!' if is_verified else 'Unconfirmed — manual review needed'}"
                        ),
                        "severity": "CRITICAL" if is_verified else "HIGH",
                        "file_path": filename.replace(self.scan_path, "").lstrip("/"),
                        "line_start": line_num,
                        "fingerprint": make_fingerprint(
                            "detect-secrets", secret_type, filename, line_num, ""
                        ),
                        "raw": {
                            "type": secret_type,
                            "line_number": line_num,
                            "is_verified": is_verified,
                            "filename": filename,
                        },
                    })

        except Exception:
            return []

        return findings

    def _collect_files(self) -> List[str]:
        """Thu thập files phù hợp để scan."""
        files = []
        skip_dirs = {
            ".git", "node_modules", "__pycache__", ".tox",
            "venv", ".venv", "env", ".env_dir",
            "dist", "build", "target", ".gradle",
        }

        for root, dirs, file_list in os.walk(self.scan_path):
            # Bỏ qua các thư mục không cần scan
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for fname in file_list:
                _, ext = os.path.splitext(fname)
                # Include nếu extension match HOẶC filename là Dockerfile/Makefile
                if ext in self.SCAN_EXTENSIONS or fname in self.SCAN_EXTENSIONS:
                    files.append(os.path.join(root, fname))

        return files
