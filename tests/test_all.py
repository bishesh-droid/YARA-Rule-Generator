import unittest
from unittest.mock import patch
import os
import shutil

from yara_generator.extractor import extract_strings
from yara_generator.scorer import _get_string_frequencies, score_strings
from yara_generator.generator import generate_yara_rule

class TestExtractor(unittest.TestCase):

    def setUp(self):
        self.test_dir = "test_extractor_dir"
        os.makedirs(self.test_dir, exist_ok=True)
        self.test_file_path = os.path.join(self.test_dir, "test_file.bin")
        patch('yara_generator.extractor.yr_logger').start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_extract_ascii_strings(self):
        content = b"This is a test string."
        with open(self.test_file_path, 'wb') as f:
            f.write(content)
        strings = extract_strings(self.test_file_path, min_len=4)
        self.assertIn("This is a test string.", strings)

    def test_extract_unicode_strings(self):
        content = b'T\x00h\x00i\x00s\x00 \x00i\x00s\x00 \x00a\x00 \x00U\x00n\x00i\x00c\x00o\x00d\x00e\x00 \x00s\x00t\x00r\x00i\x00n\x00g\x00.\x00'
        with open(self.test_file_path, 'wb') as f:
            f.write(content)
        strings = extract_strings(self.test_file_path, min_len=4)
        self.assertIn("This is a Unicode string.", strings)

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
        
        patch('yara_generator.scorer.yr_logger').start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        shutil.rmtree(self.badware_dir)
        shutil.rmtree(self.goodware_dir)

    def test_get_string_frequencies(self):
        freq = _get_string_frequencies(self.badware_dir, 4, 100)
        self.assertEqual(freq.get("malware_string_A", 0), 2)
        self.assertEqual(freq.get("common_string_X", 0), 2)

    def test_score_strings(self):
        scored = score_strings(self.badware_dir, self.goodware_dir, 4, 100)
        
        # Extract just the strings from the (string, score) tuples
        extracted_strings = [s for s, score in scored]
        
        self.assertIn("unique_malware_string_B", extracted_strings)
        self.assertIn("another_unique_string_C", extracted_strings)
        self.assertIn("malware_string_A", extracted_strings)
        self.assertNotIn("clean_string_Y", extracted_strings)
        # common_string_X should be filtered out as it's in goodware
        self.assertNotIn("common_string_X", extracted_strings)

class TestGenerator(unittest.TestCase):

    def setUp(self):
        self.output_dir = "test_rules"
        os.makedirs(self.output_dir, exist_ok=True)
        self.output_file = os.path.join(self.output_dir, "test_rule.yar")
        patch('yara_generator.generator.yr_logger').start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        shutil.rmtree(self.output_dir)

    def test_generate_yara_rule_all_of_them(self):
        rule_name = "TestRuleAll"
        strings = ["string1", "string2", "string3"]
        condition = "all of them"
        
        generated_content = generate_yara_rule(rule_name, strings, condition, self.output_file)
        
        self.assertIn("rule TestRuleAll", generated_content)
        self.assertIn("$s0 = \"string1\"", generated_content)
        # Note the space correction in the expected condition
        self.assertIn("all of ($s0, $s1, $s2)", generated_content)

    def test_generate_yara_rule_any_of_them(self):
        rule_name = "TestRuleAny"
        strings = ["stringA", "stringB"]
        condition = "any of them"
        
        generated_content = generate_yara_rule(rule_name, strings, condition, self.output_file)
        self.assertIn("any of ($s0, $s1)", generated_content)

    def test_generate_yara_rule_n_of_them(self):
        rule_name = "TestRuleN"
        strings = ["s1", "s2", "s3", "s4"]
        condition = "2 of them"
        
        generated_content = generate_yara_rule(rule_name, strings, condition, self.output_file)
        self.assertIn("2 of ($s0, $s1, $s2, $s3)", generated_content)

if __name__ == '__main__':
    unittest.main()
