import copy
import unittest

from observed_text import is_unreadable_placeholder_only


class ObservedTextTests(unittest.TestCase):
    def test_only_explicitly_unconfirmed_placeholders_are_excluded(self):
        for flag in ("uncertain", "ambiguous", "human_uncertain"):
            for text in ("□", " � □ \t", "□□"):
                line = {"text": text, flag: True, "box": [[1, 2]], "id": 4}
                before = copy.deepcopy(line)
                self.assertTrue(is_unreadable_placeholder_only(line))
                self.assertEqual(line, before)

    def test_text_numbers_and_real_symbols_remain_available(self):
        for text in ("※", "±", "℃", "°C", "*", "?", "■", "福□股份有限公司",
                     "□ 0.1公克", "2026.□1.16", "0800-200-859", "□※", ""):
            self.assertFalse(is_unreadable_placeholder_only({"text": text, "uncertain": True}), text)

    def test_confirmed_literal_square_and_nonflagged_square_are_retained(self):
        self.assertFalse(is_unreadable_placeholder_only({"text": "□"}))
        self.assertFalse(is_unreadable_placeholder_only({"text": "□", "uncertain": True,
                                                        "human_verified": True}))
        self.assertTrue(is_unreadable_placeholder_only({"text": "□", "human_uncertain": True,
                                                       "human_verified": True}))
        for line in (None, "□", {}, {"text": None}):
            self.assertFalse(is_unreadable_placeholder_only(line))


if __name__ == "__main__":
    unittest.main()
