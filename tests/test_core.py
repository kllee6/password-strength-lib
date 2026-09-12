import unittest

from password_strength import (
    char_classes,
    contains_keyboard_walk,
    estimate_entropy_bits,
    is_common_password,
    longest_repeated_run,
    longest_sequential_run,
    score,
)


class CharClassesTests(unittest.TestCase):
    def test_empty_string_has_no_classes(self):
        self.assertEqual(char_classes(""), frozenset())

    def test_mixed_password_reports_all_classes_present(self):
        classes = char_classes("Ab1 !")
        self.assertEqual(classes, frozenset({"upper", "lower", "digit", "space", "symbol"}))


class EntropyTests(unittest.TestCase):
    def test_empty_string_has_zero_entropy(self):
        self.assertEqual(estimate_entropy_bits(""), 0.0)

    def test_longer_password_has_more_entropy_than_shorter_prefix(self):
        self.assertGreater(estimate_entropy_bits("correcthorse"), estimate_entropy_bits("correct"))

    def test_wider_charset_has_more_entropy_than_same_length_lowercase(self):
        self.assertGreater(estimate_entropy_bits("Ab1!cdef"), estimate_entropy_bits("abcdefgh"))


class PatternDetectionTests(unittest.TestCase):
    def test_detects_ascending_sequential_run(self):
        self.assertEqual(longest_sequential_run("x9abcdy2"), 4)

    def test_detects_descending_sequential_run(self):
        self.assertEqual(longest_sequential_run("9876"), 4)

    def test_no_sequential_run_in_random_looking_string(self):
        self.assertLess(longest_sequential_run("k3jd8fq1"), 3)

    def test_detects_repeated_run(self):
        self.assertEqual(longest_repeated_run("aaabbc"), 3)

    def test_detects_keyboard_walk(self):
        self.assertTrue(contains_keyboard_walk("myqwertypass"))

    def test_no_keyboard_walk_in_unrelated_string(self):
        self.assertFalse(contains_keyboard_walk("kj3mdlq9"))


class CommonPasswordTests(unittest.TestCase):
    def test_common_password_is_flagged_case_insensitively(self):
        self.assertTrue(is_common_password("PaSsWoRd"))

    def test_uncommon_password_is_not_flagged(self):
        self.assertFalse(is_common_password("kj3mdlq9zP"))


class ScoreTests(unittest.TestCase):
    def test_empty_password_scores_zero(self):
        result = score("")
        self.assertEqual(result.score, 0)
        self.assertIn("empty password", result.warnings)

    def test_common_password_scores_zero_even_if_long(self):
        result = score("administrator")
        self.assertEqual(result.score, 0)

    def test_short_simple_password_scores_low(self):
        result = score("abc123")
        self.assertLessEqual(result.score, 1)

    def test_long_mixed_password_scores_higher_than_short_simple_one(self):
        weak = score("abc123")
        strong = score("Tr0ub4dour&9xQ!lm")
        self.assertGreater(strong.score, weak.score)

    def test_score_is_deterministic(self):
        self.assertEqual(score("kj3mdlq9zP!"), score("kj3mdlq9zP!"))


if __name__ == "__main__":
    unittest.main()
