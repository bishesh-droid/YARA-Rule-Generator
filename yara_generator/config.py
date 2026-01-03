# yara_generator/config.py

import os

# Minimum length for extracted strings
MIN_STRING_LENGTH = 8

# Maximum length for extracted strings
MAX_STRING_LENGTH = 256

# Number of top-scoring strings to include in the generated YARA rule
TOP_STRINGS_COUNT = 20

# Default condition for the YARA rule (e.g., "any of them", "all of them", "N of them")
# If using "N of them", specify the number, e.g., "5 of them"
DEFAULT_RULE_CONDITION = "all of them"

# Path for the YARA Generator log file
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'yara_generator.log')

# Verbosity level for console output
VERBOSE_CONSOLE_OUTPUT = True
