import csv
import io
import json
import unittest

from wg_handshake_overlay.scenarios import SCENARIO_PAIRS, format_results, run_scenarios


class ScenarioTests(unittest.TestCase):
    def test_canonical_matrix_has_27_connections(self):
        self.assertEqual(
            {name: len(pairs) for name, pairs in SCENARIO_PAIRS.items()},
            {"bidir12": 2, "disjoint5": 5, "ring10": 10, "reverse5": 10},
        )
        self.assertEqual(sum(len(pairs) for pairs in SCENARIO_PAIRS.values()), 27)

    def test_all_contract_scenarios_pass(self):
        rows = run_scenarios()
        self.assertEqual(len(rows), 27)
        self.assertTrue(all(row["model_ok"] for row in rows))
        self.assertTrue(all(row["direct_wg_control_packets"] == 0 for row in rows))
        self.assertTrue(all(row["direct_transport_packets"] == 1 for row in rows))
        self.assertTrue(all(row["injected_control_packets"] == 2 for row in rows))

    def test_json_and_csv_are_machine_readable(self):
        json_rows = json.loads(format_results("json"))
        csv_rows = list(csv.DictReader(io.StringIO(format_results("csv"))))
        self.assertEqual(len(json_rows), 27)
        self.assertEqual(len(csv_rows), 27)
        self.assertEqual(set(row["scenario"] for row in json_rows), set(SCENARIO_PAIRS))
