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

def score_strings(badware_dir: str, goodware_dir: str, min_len: int = MIN_STRING_LENGTH, max_len: int = MAX_STRING_LENGTH) -> list[str]:
    """
    Scores strings based on their presence in badware vs. goodware directories.
    Returns a list of top-scoring unique strings suitable for YARA rules.

    Args:
        badware_dir (str): Path to the directory containing malware samples.
        goodware_dir (str): Path to the directory containing clean files.
        min_len (int): Minimum length of strings to consider.
        max_len (int): Maximum length of strings to consider.

    Returns:
        list: A list of top-scoring unique strings.
    """
    yr_logger.info(f"[*] Scoring strings from badware: {badware_dir} and goodware: {goodware_dir}")

    badware_strings_freq = _get_string_frequencies(badware_dir, min_len, max_len)
    goodware_strings_freq = _get_string_frequencies(goodware_dir, min_len, max_len)

    scored_strings = {}
    for s, badware_count in badware_strings_freq.items():
        goodware_count = goodware_strings_freq.get(s, 0)
        
        # Simple scoring: higher if more in badware, lower if more in goodware
        # Prioritize strings unique to badware
        if goodware_count == 0 and badware_count > 0:
            score = badware_count * 1000 # High score for unique badware strings
        elif badware_count > 0:
            score = badware_count / (goodware_count + 1) # +1 to avoid division by zero
        else:
            score = 0
        
        scored_strings[s] = score

    # Sort strings by score in descending order
    sorted_strings = sorted(scored_strings.items(), key=lambda item: item[1], reverse=True)

    # Filter out strings that also appear frequently in goodware (even if not unique)
    # This is a heuristic and can be refined.
    final_strings = []
    for s, score in sorted_strings:
        if goodware_strings_freq.get(s, 0) < badware_strings_freq.get(s, 0) and score > 0: # Heuristic: less frequent in goodware
            final_strings.append(s)
        if len(final_strings) >= TOP_STRINGS_COUNT:
            break

    yr_logger.info(f"[+] Identified {len(final_strings)} top-scoring strings.")
    return final_strings
