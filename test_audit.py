"""
test_audit.py — tests for CyberAudit toolkit
Run:  pytest test_audit.py -v
"""
import hashlib
import os
import pytest
import audit as mod


# ── calc_entropy ──────────────────────────────────────────────────────────────

def test_entropy_lowercase_only():
    # pool = 26, length = 4 → 4 * log2(26) ≈ 18.8
    e = mod.calc_entropy("abcd")
    assert 18 < e < 20


def test_entropy_mixed():
    # Upper + lower + digit + symbol → pool 94
    e = mod.calc_entropy("Abc1!")
    assert e > 20


def test_entropy_empty():
    assert mod.calc_entropy("") == 0.0


def test_entropy_increases_with_length():
    short = mod.calc_entropy("abc")
    long_ = mod.calc_entropy("abcdefgh")
    assert long_ > short


# ── score_password ────────────────────────────────────────────────────────────

class TestScorePassword:
    def test_strong_password(self):
        result = mod.score_password("X9#mQz@vL2$wKp8!")
        assert result["score"] >= 70
        assert result["rating"] in ("Strong", "Moderate")

    def test_common_password_penalised(self):
        result = mod.score_password("password")
        assert result["score"] < 30
        assert any("commonly" in t.lower() for t in result["tips"])

    def test_short_password_tips(self):
        result = mod.score_password("ab")
        tips_text = " ".join(result["tips"]).lower()
        assert "8 characters" in tips_text or "length" in tips_text or result["score"] < 50

    def test_keyboard_walk_penalised(self):
        result = mod.score_password("qwerty123")
        assert any("keyboard" in t.lower() or "qwerty" in t.lower() for t in result["tips"])

    def test_no_uppercase_tip(self):
        result = mod.score_password("abc123!@#")
        assert any("uppercase" in t.lower() for t in result["tips"])

    def test_no_symbol_tip(self):
        result = mod.score_password("Abcdef123")
        assert any("symbol" in t.lower() for t in result["tips"])

    def test_score_bounded(self):
        for pw in ("", "a", "password", "X9#mQz@vL2$wKp8!"):
            result = mod.score_password(pw)
            assert 0 <= result["score"] <= 100

    def test_returns_required_keys(self):
        result = mod.score_password("Test1234!")
        assert {"score", "rating", "entropy_bits", "tips"} <= result.keys()


# ── generate_password ─────────────────────────────────────────────────────────

class TestGeneratePassword:
    def test_default_length(self):
        pw = mod.generate_password()
        assert len(pw) == 16

    def test_custom_length(self):
        pw = mod.generate_password(length=24)
        assert len(pw) == 24

    def test_has_uppercase(self):
        pw = mod.generate_password(length=20)
        assert any(c.isupper() for c in pw)

    def test_has_lowercase(self):
        pw = mod.generate_password(length=20)
        assert any(c.islower() for c in pw)

    def test_has_digit(self):
        pw = mod.generate_password(length=20)
        assert any(c.isdigit() for c in pw)

    def test_no_symbols(self):
        import string
        pw = mod.generate_password(length=20, use_symbols=False)
        assert not any(c in string.punctuation for c in pw)

    def test_uniqueness(self):
        # Two generated passwords should almost never be identical
        pws = {mod.generate_password() for _ in range(10)}
        assert len(pws) > 1


# ── hash_file ─────────────────────────────────────────────────────────────────

class TestHashFile:
    def test_sha256(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_bytes(b"hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert mod.hash_file(str(f), "sha256") == expected

    def test_md5(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_bytes(b"test")
        expected = hashlib.md5(b"test").hexdigest()
        assert mod.hash_file(str(f), "md5") == expected

    def test_sha512(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_bytes(b"abc")
        expected = hashlib.sha512(b"abc").hexdigest()
        assert mod.hash_file(str(f), "sha512") == expected

    def test_missing_file_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            mod.hash_file(str(tmp_path / "nonexistent.txt"))

    def test_same_content_same_hash(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_bytes(b"same")
        b.write_bytes(b"same")
        assert mod.hash_file(str(a)) == mod.hash_file(str(b))

    def test_different_content_different_hash(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_bytes(b"foo")
        b.write_bytes(b"bar")
        assert mod.hash_file(str(a)) != mod.hash_file(str(b))


# ── scan_logs ─────────────────────────────────────────────────────────────────

class TestScanLogs:
    def _write_log(self, tmp_path, lines):
        p = tmp_path / "auth.log"
        p.write_text("\n".join(lines) + "\n")
        return str(p)

    def test_no_threats(self, tmp_path):
        log = self._write_log(tmp_path, [
            "User alice logged in successfully.",
            "System startup complete.",
        ])
        findings = mod.scan_logs(log)
        assert findings == []

    def test_ssh_failed_login(self, tmp_path):
        log = self._write_log(tmp_path, [
            "Failed password for invalid user root from 192.168.1.10 port 22 ssh2",
        ])
        findings = mod.scan_logs(log)
        assert len(findings) == 1
        assert findings[0]["line_num"] == 1

    def test_sudo_failure(self, tmp_path):
        log = self._write_log(tmp_path, [
            "sudo: pam_unix(sudo:auth): authentication failure; user=bob",
            "sudo: bob : FAILED 3 incorrect password attempts",
        ])
        findings = mod.scan_logs(log)
        assert len(findings) >= 1

    def test_multiple_threats(self, tmp_path):
        log = self._write_log(tmp_path, [
            "Failed password for invalid user root from 10.0.0.1 port 22 ssh2",
            "Failed password for invalid user admin from 10.0.0.2 port 22 ssh2",
            "Normal log line",
            "sudo: alice : FAILED 1 incorrect password attempt",
        ])
        findings = mod.scan_logs(log)
        assert len(findings) >= 3

    def test_missing_file_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            mod.scan_logs(str(tmp_path / "no_such.log"))


# ── scan_directory ────────────────────────────────────────────────────────────

class TestScanDirectory:
    def test_basic_scan(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"aaa")
        (tmp_path / "b.txt").write_bytes(b"bbb")
        results = mod.scan_directory(str(tmp_path))
        assert len(results) == 2
        paths = {r["path"] for r in results}
        assert any("a.txt" in p for p in paths)
        assert any("b.txt" in p for p in paths)

    def test_hash_correct(self, tmp_path):
        f = tmp_path / "check.txt"
        f.write_bytes(b"verify me")
        results = mod.scan_directory(str(tmp_path))
        assert len(results) == 1
        expected = hashlib.sha256(b"verify me").hexdigest()
        assert results[0]["hash"] == expected

    def test_empty_directory(self, tmp_path):
        subdir = tmp_path / "empty"
        subdir.mkdir()
        results = mod.scan_directory(str(subdir))
        assert results == []

    def test_not_a_directory_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            mod.scan_directory(str(tmp_path / "nonexistent"))

    def test_md5_algorithm(self, tmp_path):
        f = tmp_path / "f.txt"
        f.write_bytes(b"md5test")
        results = mod.scan_directory(str(tmp_path), algorithm="md5")
        expected = hashlib.md5(b"md5test").hexdigest()
        assert results[0]["hash"] == expected

    def test_recursive_scan(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "root.txt").write_bytes(b"r")
        (sub / "nested.txt").write_bytes(b"n")
        results = mod.scan_directory(str(tmp_path))
        assert len(results) == 2
