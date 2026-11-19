"""Offline guardrails: weekly source polling, separately documented daily client polling."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ScheduleTests(unittest.TestCase):
    def test_github_runs_every_sunday_only(self):
        workflow = (ROOT / '.github/workflows/main.yml').read_text(encoding='utf-8')
        self.assertRegex(workflow, r'cron:\s*["\']17 3 \* \* 0["\']')
        self.assertNotIn('17 3 * * *', workflow)

    def test_push_retries_rebuild_from_latest_database_without_force(self):
        workflow = (ROOT / '.github/workflows/main.yml').read_text(encoding='utf-8')
        for expected in ('ref: main', 'fetch-depth: 0', 'git fetch origin main',
                         'git reset --hard origin/main', 'for attempt in 1 2 3',
                         'git push origin HEAD:main', 'QALQON_API_CACHE:'):
            self.assertIn(expected, workflow)
        self.assertNotIn('git push --force', workflow)
        self.assertNotIn('git pull --rebase', workflow)

    def test_android_daily_check_is_documented_not_misrepresented(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        self.assertIn('Every 24 hours in the Android app', readme)
        self.assertIn('must be implemented in QALQON itself', readme)
        self.assertIn('2 API calls per week', readme)
        self.assertIn('100,000,000 bytes uncompressed', readme)


if __name__ == '__main__':
    unittest.main()
