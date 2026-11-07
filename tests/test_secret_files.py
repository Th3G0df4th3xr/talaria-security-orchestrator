import pytest

from talaria.security.secrets import SecretFileError, read_secret_file


def test_nonempty_secret_requires_owner_only_permissions(tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_text("private-value\n", encoding="utf-8")
    secret_file.chmod(0o640)

    with pytest.raises(SecretFileError, match="group/world-readable"):
        read_secret_file(secret_file, label="test")


def test_private_secret_file_is_read_and_trimmed(tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_text("private-value\n", encoding="utf-8")
    secret_file.chmod(0o400)

    assert read_secret_file(secret_file, label="test") == "private-value"


def test_empty_optional_secret_file_can_be_a_placeholder(tmp_path):
    secret_file = tmp_path / "optional"
    secret_file.write_text("\n", encoding="utf-8")

    assert read_secret_file(secret_file, label="test", allow_empty=True) == ""


def test_secret_path_must_be_a_regular_file(tmp_path):
    with pytest.raises(SecretFileError, match="secret file"):
        read_secret_file(tmp_path, label="test")


def test_secret_symlinks_are_rejected(tmp_path):
    actual = tmp_path / "actual"
    actual.write_text("private-value", encoding="utf-8")
    actual.chmod(0o400)
    link = tmp_path / "secret-link"
    link.symlink_to(actual)

    with pytest.raises(SecretFileError, match="Cannot read"):
        read_secret_file(link, label="test")
