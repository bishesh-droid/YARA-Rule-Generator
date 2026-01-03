import os
from datetime import datetime
from typing import List

from .logger import yr_logger
from .config import DEFAULT_RULE_CONDITION

def generate_yara_rule(rule_name: str, strings: List[str], condition_type: str = DEFAULT_RULE_CONDITION, output_file: str = None):
    """
    Generates a YARA rule based on a list of strings and a condition type.

    Args:
        rule_name (str): The name of the YARA rule.
        strings (List[str]): A list of strings to include in the rule.
        condition_type (str): The condition for the rule (e.g., "all of them", "any of them", "N of them").
        output_file (str, optional): Path to save the YARA rule file. If None, prints to console.
    """
    yr_logger.info(f"[*] Generating YARA rule '{rule_name}'...")

    rule_content = []
    rule_content.append(f"rule {rule_name}")
    rule_content.append("{")
    rule_content.append("    meta:")
    rule_content.append(f"        author = \"YARA Rule Generator\"")
    rule_content.append(f"        date = \"{datetime.now().strftime('%Y-%m-%d')}\"")
    rule_content.append(f"        description = \"Automatically generated rule for {rule_name}\"")
    rule_content.append("")

    rule_content.append("    strings:")
    if not strings:
        rule_content.append("        // No significant strings found to generate rule.")
        rule_content.append("        // This rule will always be false.")
        rule_content.append("        $dummy = \"this string should not exist\"")
    else:
        for i, s in enumerate(strings):
            # Escape double quotes and backslashes in the string
            escaped_s = s.replace('\\', '\\\\').replace('"', '\"')
            rule_content.append(f"        $s{i} = \"{escaped_s}\"")
    rule_content.append("")

    rule_content.append("    condition:")
    if not strings:
        rule_content.append("        false")
    else:
        string_identifiers = [f"$s{i}" for i in range(len(strings))]
        if condition_type.lower() == "all of them":
            rule_content.append(f"        all of ({ ', '.join(string_identifiers) })")
        elif condition_type.lower() == "any of them":
            rule_content.append(f"        any of ({ ', '.join(string_identifiers) })")
        elif "of them" in condition_type.lower():
            try:
                num = int(condition_type.lower().split(' ')[0])
                rule_content.append(f"        {num} of ({ ', '.join(string_identifiers) })")
            except ValueError:
                yr_logger.warning(f"[WARN] Invalid condition type '{condition_type}'. Defaulting to 'any of them'.")
                rule_content.append(f"        any of ({ ', '.join(string_identifiers) })")
        else:
            yr_logger.warning(f"[WARN] Invalid condition type '{condition_type}'. Defaulting to 'any of them'.")
            rule_content.append(f"        any of ({ ', '.join(string_identifiers) })")

    rule_content.append("}")

    final_rule = "\n".join(rule_content)

    if output_file:
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(final_rule)
            yr_logger.info(f"[+] YARA rule saved to: {output_file}")
        except Exception as e:
            yr_logger.error(f"[ERROR] Failed to save YARA rule to {output_file}: {e}")
            raise
    else:
        yr_logger.info("[+] YARA rule generated (printed to console).")
        print(final_rule)

    return final_rule
