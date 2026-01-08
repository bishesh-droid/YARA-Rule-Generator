import os
from collections import defaultdict

from .logger import yr_logger
from .extractor import extract_strings
from .config import MIN_STRING_LENGTH, MAX_STRING_LENGTH, TOP_STRINGS_COUNT

def _get_string_frequencies(directory: str, min_len: int, max_len: int) -> dict[str, int]:
    """
    Extracts strings from all files in a directory and returns their frequencies.
    """
    all_strings = defaultdict(int)
    if not os.path.exists(directory):
        yr_logger.warning(f"[SCORER] Directory not found: {directory}. Skipping string extraction.")
        return dict(all_strings)

    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            strings_in_file = extract_strings(file_path, min_len, max_len)
            for s in strings_in_file:
                all_strings[s] += 1
    return dict(all_strings)

def score_strings(badware_dir: str, goodware_dir: str, min_len: int = MIN_STRING_LENGTH, max_len: int = MAX_STRING_LENGTH) -> list[tuple[str, float]]:
    """
    Scores strings based on their presence in badware vs. goodware directories.
    Returns a sorted list of strings and their scores.

    Args:
        badware_dir (str): Path to the directory containing malware samples.
        goodware_dir (str): Path to the directory containing clean files.
        min_len (int): Minimum length of strings to consider.
        max_len (int): Maximum length of strings to consider.

    Returns:
        list[tuple[str, float]]: A list of (string, score) tuples, sorted by score in descending order.
    """
    yr_logger.info(f"[*] Scoring strings from badware: {badware_dir} and goodware: {goodware_dir}")

    badware_strings_freq = _get_string_frequencies(badware_dir, min_len, max_len)
    goodware_strings_freq = _get_string_frequencies(goodware_dir, min_len, max_len) if goodware_dir else {}

    scored_strings = {}
    for s, badware_count in badware_strings_freq.items():
        goodware_count = goodware_strings_freq.get(s, 0)
        
        # Scoring algorithm: prioritize strings unique to badware
        if goodware_count > 0:
            score = 0  # Penalize heavily if in goodware
        else:
            score = badware_count * 100  # High score for unique badware strings
        
        if score > 0:
            scored_strings[s] = score

    # Sort strings by score in descending order
    sorted_strings = sorted(scored_strings.items(), key=lambda item: item[1], reverse=True)

    yr_logger.info(f"[+] Scored {len(sorted_strings)} candidate strings.")
    return sorted_strings
