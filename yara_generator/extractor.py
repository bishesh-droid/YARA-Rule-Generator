import os
import re

from .logger import yr_logger
from .config import MIN_STRING_LENGTH, MAX_STRING_LENGTH

def extract_strings(file_path: str, min_len: int = MIN_STRING_LENGTH, max_len: int = MAX_STRING_LENGTH) -> list[str]:
    """
    Extracts printable ASCII and Unicode strings from a binary file.

    Args:
        file_path (str): The path to the binary file.
        min_len (int): Minimum length of strings to extract.
        max_len (int): Maximum length of strings to extract.

    Returns:
        list: A list of unique extracted strings.
    """
    if not os.path.exists(file_path):
        yr_logger.error(f"[ERROR] File not found: {file_path}")
        return []

    extracted = set()
    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        # ASCII strings
        # Regex to find sequences of printable ASCII characters
        ascii_strings = re.findall(rb'[\x20-\x7E]{%d,%d}' % (min_len, max_len), content)
        for s in ascii_strings:
            extracted.add(s.decode('ascii', errors='ignore').strip())

        # Unicode strings (UTF-16 Little Endian)
        # More reliable method to find UTF-16LE strings
        unicode_strings = re.findall(rb'(?:[\x20-\x7E]\x00){%d,}' % min_len, content)
        for s in unicode_strings:
            try:
                decoded_s = s.decode('utf-16-le').strip()
                if len(decoded_s) <= max_len:
                    extracted.add(decoded_s)
            except UnicodeDecodeError:
                yr_logger.debug(f"Unicode decode error for string in {file_path}")
                pass # Ignore if not valid unicode

    except Exception as e:
        yr_logger.error(f"[ERROR] Failed to extract strings from {file_path}: {e}")

    yr_logger.debug(f"[EXTRACTOR] Extracted {len(extracted)} unique strings from {file_path}")
    return list(extracted)