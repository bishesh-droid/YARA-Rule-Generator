import unittest
from unittest.mock import patch, MagicMock
import os
import shutil

from yara_generator.extractor import extract_strings
from yara_generator.scorer import _get_string_frequencies, score_strings
from yara_generator.generator import generate_yara_rule
from yara_generator.config import MIN_STRING_LENGTH, MAX_STRING_LENGTH, TOP_STRINGS_COUNT

class TestExtractor(unittest.TestCase):

    def setUp(self):
        self.test_dir = "test_extractor_dir"
        os.makedirs(self.test_dir, exist_ok=True)
        self.test_file_path = os.path.join(self.test_dir, "test_file.bin")
        # Mock logger
        patch('yara_generator.extractor.yr_logger').start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_extract_ascii_strings(self):
        content = b"\x00\x01\x02This is an ASCII string.\x03\x04Another string here.\x05"
        with open(self.test_file_path, 'wb') as f:
            f.write(content)
        
        strings = extract_strings(self.test_file_path, min_len=4)
        self.assertIn("This is an ASCII string.", strings)
        self.assertIn("Another string here.", strings)
        self.assertEqual(len(strings), 2)

    def test_extract_unicode_strings(self):
        content = b"\x00\x01\x02T\x00h\x00i\x00s\x00 \x00i\x00s\x00 \x00U\x00n\x00i\x00c\x00o\x00d\x00e\x00.\x00\x03\x04"
        with open(self.test_file_path, 'wb') as f:
            f.write(content)
        
        strings = extract_strings(self.test_file_path, min_len=4)
        self.assertIn("This is Unicode.", strings)
        self.assertEqual(len(strings), 1)

    def test_extract_strings_min_max_len(self):
        content = b"short\nlong_enough\nvery_very_long_string"
        with open(self.test_file_path, 'wb') as f:
            f.write(content)
        
        strings = extract_strings(self.test_file_path, min_len=10, max_len=15)
        self.assertIn("long_enough", strings)
        self.assertNotIn("short", strings)
        self.assertNotIn("very_very_long_string", strings)

class TestScorer(unittest.TestCase):

    def setUp(self):
        self.badware_dir = "test_badware"
        self.goodware_dir = "test_goodware"
        os.makedirs(self.badware_dir, exist_ok=True)
        os.makedirs(self.goodware_dir, exist_ok=True)

        with open(os.path.join(self.badware_dir, "malware1.bin"), 'w') as f:
            f.write("malware_string_A\nunique_malware_string_B\ncommon_string_X")
        with open(os.path.join(self.badware_dir, "malware2.bin"), 'w') as f:
            f.write("malware_string_A\nanother_unique_string_C\ncommon_string_X")
        with open(os.path.join(self.goodware_dir, "clean1.bin"), 'w') as f:
            f.write("clean_string_Y\ncommon_string_X")
        with open(os.path.join(self.goodware_dir, "clean2.bin"), 'w') as f:
            f.write("clean_string_Z\ncommon_string_X")
        # Mock logger
        patch('yara_generator.scorer.yr_logger').start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        if os.path.exists(self.badware_dir):
            shutil.rmtree(self.badware_dir)
        if os.path.exists(self.goodware_dir):
            shutil.rmtree(self.goodware_dir)

    def test_get_string_frequencies(self):
        freq = _get_string_frequencies(self.badware_dir, 4, 100)
        self.assertEqual(freq["malware_string_A"], 2)
        self.assertEqual(freq["common_string_X"], 2)

    def test_score_strings(self):
        scored = score_strings(self.badware_dir, self.goodware_dir, 4, 100)
        # Expect unique_malware_string_B and another_unique_string_C to score high
        # malware_string_A also high
        # common_string_X should be lower due to presence in goodware
        self.assertIn("unique_malware_string_B", scored)
        self.assertIn("another_unique_string_C", scored)
        self.assertIn("malware_string_A", scored)
        self.assertNotIn("clean_string_Y", scored)
        self.assertNotIn("clean_string_Z", scored)

class TestGenerator(unittest.TestCase):

    def setUp(self):
        self.output_dir = "test_rules"
        os.makedirs(self.output_dir, exist_ok=True)
        self.output_file = os.path.join(self.output_dir, "test_rule.yar")
        # Mock logger
        patch('yara_generator.generator.yr_logger').start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)

    def test_generate_yara_rule_all_of_them(self):
        rule_name = "TestRule"
        strings = ["string1", "string2", "string3"]
        condition_type = "all of them"
        
        generated_content = generate_yara_rule(rule_name, strings, condition_type, self.output_file)
        self.assertTrue(os.path.exists(self.output_file))
        self.assertIn("rule TestRule", generated_content)
        self.assertIn("$s0 = \"string1\"", generated_content)
        self.assertIn("condition:\n        all of ($s0, $s1, $s2)", generated_content)

    def test_generate_yara_rule_any_of_them(self):
        rule_name = "TestRuleAny"
        strings = ["stringA", "stringB"]
        condition_type = "any of them"
        
        generated_content = generate_yara_rule(rule_name, strings, condition_type, self.output_file)
        self.assertIn("condition:\n        any of ($s0, $s1)", generated_content)

    def test_generate_yara_rule_n_of_them(self):
        rule_name = "TestRuleN"
        strings = ["s1", "s2", "s3", "s4", "s5"]
        condition_type = "3 of them"
        
        generated_content = generate_yara_rule(rule_name, strings, condition_type, self.output_file)
        self.assertIn("condition:\n        3 of ($s0, $s1, $s2, $s3, $s4)", generated_content)

    def test_generate_yara_rule_no_strings(self):
        rule_name = "TestRuleNoStrings"
        strings = []
        condition_type = "any of them"
        
        generated_content = generate_yara_rule(rule_name, strings, condition_type, self.output_file)
        self.assertIn("condition:\n        false", generated_content)
        self.assertIn("$dummy = \"this string should not exist\"", generated_content)

if __name__ == '__main__':
    unittest.main()
