"""Exercise the actual manual workflow guard without tags, uploads or GitHub access."""
import os
from pathlib import Path
import subprocess
import textwrap
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class ReleaseGuard(unittest.TestCase):
    def guard(self, ref_type, ref_name, tag_code=0, tag_sha='head'):
        workflow = (ROOT/'.github/workflows/release.yml').read_text()
        script = textwrap.dedent(workflow.split("python3 - <<'PYTHON'", 1)[1]
                                 .split('          PYTHON', 1)[0]).strip()
        with patch.dict(os.environ, {'REF_TYPE': ref_type, 'REF_NAME': ref_name}), \
             patch.object(Path, 'read_text', return_value='[project]\nversion="0.1.2"\n'), \
             patch.object(subprocess, 'check_output', return_value='head\n'), \
             patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], tag_code, tag_sha+'\n', '')):
            exec(compile(script, 'release.yml guard', 'exec'), {})

    def test_main_requires_a_tag_pointing_to_the_exact_checked_commit(self):
        self.guard('branch', 'main')
        for code, sha in [(1, ''), (0, 'other-commit')]:
            with self.subTest(code=code, sha=sha), self.assertRaises(SystemExit):
                self.guard('branch', 'main', code, sha)

    def test_tag_or_feature_branch_cannot_publish_through_main_only_environment(self):
        for kind, name in [('tag', 'v0.1.2'), ('branch', 'feature')]:
            with self.subTest(kind=kind), self.assertRaises(SystemExit):
                self.guard(kind, name)
