import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'candidate'))
import runtime_contract as runtime


class RuntimeTests(unittest.TestCase):
    def test_actual_qualified_runtime(self):
        runtime.require_runtime()

    def test_wrong_interpreter_rejected(self):
        for version in ((3, 10, 12), (3, 14, 7), (3, 15, 0)):
            with self.subTest(version=version), self.assertRaises(RuntimeError):
                runtime.check_versions(version, '50.0.2')

    def test_wrong_library_rejected(self):
        for version in ('3.4.8', '43.0.0', '46.0.4'):
            with self.subTest(version=version), self.assertRaises(RuntimeError):
                runtime.check_versions((3, 14, 8), version)


if __name__ == '__main__':
    unittest.main(verbosity=2)
