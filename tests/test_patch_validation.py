import json

import pytest

from talaria.integrations.llm import LLMSettings
from talaria.remediation.patches import (
    MAX_PATCH_RESPONSE_BYTES,
    LLMPatchGenerator,
    PatchValidationError,
    PatchValidator,
)


class FakeProvider:
    def __init__(self, content):
        self.content = content
        self.system_prompt = ""
        self.user_prompt = ""

    def complete(self, system_prompt, user_prompt):
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        return self.content


def unified_diff(old, new, path="app.py"):
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -1 +1 @@\n"
        f"-{old}\n"
        f"+{new}\n"
    )


def test_patch_is_checked_in_temporary_copy_only(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")

    result = PatchValidator().validate(
        root,
        unified_diff("value = 1", "value = 2"),
        {"app.py"},
    )

    assert result.changed_files == ("app.py",)
    assert result.python_files_syntax_valid is True
    assert result.applied_to_temporary_copy is True
    assert result.original_repository_modified is False
    assert result.file_contents == (("app.py", b"value = 2\n"),)
    assert len(result.patch_sha256) == 64
    assert result.file_modes == (("app.py", "100644"),)
    assert (root / "app.py").read_text(encoding="utf-8") == "value = 1\n"


@pytest.mark.parametrize(
    ("diff", "allowed", "error"),
    [
        (unified_diff("value = 1", "value = 2", "../outside.py"), {"../outside.py"}, "path"),
        (unified_diff("value = 1", "value = 2"), {"other.py"}, "approved set"),
        (unified_diff("value = 1", "def invalid(:"), {"app.py"}, "syntax"),
    ],
)
def test_patch_validator_rejects_invalid_proposals(tmp_path, diff, allowed, error):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(PatchValidationError, match=error):
        PatchValidator().validate(root, diff, allowed)

    assert (root / "app.py").read_text(encoding="utf-8") == "value = 1\n"


def test_patch_validator_rejects_oversized_patch(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(PatchValidationError, match="size limit"):
        PatchValidator(max_patch_bytes=32).validate(
            root,
            unified_diff("value = 1", "value = 2"),
            {"app.py"},
        )


def test_patch_validator_rejects_mode_changes(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    diff = """diff --git a/app.py b/app.py
old mode 100644
new mode 100755
"""

    with pytest.raises(PatchValidationError, match="mode changes"):
        PatchValidator().validate(root, diff, {"app.py"})


def test_llm_patch_generator_requires_explicit_source_sharing(tmp_path):
    generator = LLMPatchGenerator(
        FakeProvider("{}"),
        LLMSettings(enabled=True, send_source=False),
    )

    with pytest.raises(PatchValidationError, match="source-sharing consent"):
        generator.generate(tmp_path, {}, {"app.py": "value = 1"}, "a" * 40)


def test_llm_patch_generator_checks_base_and_applies_only_in_temp(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    import subprocess

    subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "Test User"], check=True
    )
    subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", "base"],
        check=True,
        capture_output=True,
    )
    from git import Repo

    base_sha = Repo(root).head.commit.hexsha
    payload = json.dumps(
        {
            "summary": "Update value safely",
            "base_sha": base_sha,
            "diff": unified_diff("value = 1", "value = 2"),
        }
    )
    generator = LLMPatchGenerator(
        FakeProvider(payload),
        LLMSettings(enabled=True, send_source=True),
    )

    proposal, validation = generator.generate(
        root,
        {"rule_id": "example"},
        {"app.py": "value = 1\n"},
        base_sha,
    )

    assert proposal.summary == "Update value safely"
    assert validation.changed_files == ("app.py",)
    assert (root / "app.py").read_text(encoding="utf-8") == "value = 1\n"


def test_llm_patch_generator_rejects_oversized_provider_response(tmp_path):
    import subprocess

    from git import Repo

    root = tmp_path / "repo"
    root.mkdir()
    source = "value = 1\n"
    (root / "app.py").write_text(source, encoding="utf-8")
    subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "Test User"], check=True
    )
    subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", "base"],
        check=True,
        capture_output=True,
    )
    base_sha = Repo(root).head.commit.hexsha
    generator = LLMPatchGenerator(
        FakeProvider(" " * (MAX_PATCH_RESPONSE_BYTES + 1)),
        LLMSettings(enabled=True, send_source=True),
    )

    with pytest.raises(PatchValidationError, match="size limit"):
        generator.generate(root, {}, {"app.py": source}, base_sha)


def test_llm_patch_generator_redacts_source_and_finding_before_provider(tmp_path):
    import subprocess

    from git import Repo

    secret = "sensitive-provider-credential-value"
    root = tmp_path / "repo"
    root.mkdir()
    source = f"api_key = '{secret}'\nvalue = 1\n"
    (root / "app.py").write_text(source, encoding="utf-8")
    subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "Test User"], check=True
    )
    subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", "base"],
        check=True,
        capture_output=True,
    )
    base_sha = Repo(root).head.commit.hexsha
    provider = FakeProvider(
        json.dumps(
            {
                "summary": "Update value safely",
                "base_sha": base_sha,
                "diff": (
                    "diff --git a/app.py b/app.py\n"
                    "--- a/app.py\n+++ b/app.py\n"
                    "@@ -2 +2 @@\n-value = 1\n+value = 2\n"
                ),
            }
        )
    )

    LLMPatchGenerator(
        provider, LLMSettings(enabled=True, send_source=True)
    ).generate(
        root,
        {"title": f"api_key={secret}"},
        {"app.py": source},
        base_sha,
    )

    assert secret not in provider.user_prompt
    assert "[REDACTED]" in provider.user_prompt


def test_llm_patch_generator_rejects_credential_in_model_patch(tmp_path):
    import subprocess

    from git import Repo

    root = tmp_path / "repo"
    root.mkdir()
    source = "value = 1\n"
    (root / "app.py").write_text(source, encoding="utf-8")
    subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "Test User"], check=True
    )
    subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", "base"],
        check=True,
        capture_output=True,
    )
    base_sha = Repo(root).head.commit.hexsha
    fake_token = "".join(["ghp_", "123456789012345678901234567890123456"])
    leaked_patch = unified_diff("value = 1", f"value = '{fake_token}'")
    provider = FakeProvider(
        json.dumps(
            {
                "summary": "Update value",
                "base_sha": base_sha,
                "diff": leaked_patch,
            }
        )
    )

    with pytest.raises(PatchValidationError, match="credential material"):
        LLMPatchGenerator(
            provider, LLMSettings(enabled=True, send_source=True)
        ).generate(root, {}, {"app.py": source}, base_sha)
