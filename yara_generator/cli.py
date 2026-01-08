import click
import sys
import os

from .extractor import extract_strings
from .scorer import score_strings
from .generator import generate_yara_rule
from .logger import yr_logger
from .config import MIN_STRING_LENGTH, MAX_STRING_LENGTH, TOP_STRINGS_COUNT, DEFAULT_RULE_CONDITION

@click.group()
def cli():
    """
    YARA Rule Generator CLI.
    Automates the creation of YARA rules based on malware and goodware samples.
    """
    pass

@cli.command()
@click.argument('badware_dir', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--goodware-dir', '-g', type=click.Path(exists=True, file_okay=False, dir_okay=True),
              help='Path to a directory containing clean files (goodware) for scoring.')
@click.option('--rule-name', '-n', default='GeneratedMalwareRule',
              help='Name for the generated YARA rule.')
@click.option('--output-file', '-o', type=click.Path(), default='rules/generated_rule.yar',
              help='Output path for the generated YARA rule file.')
@click.option('--min-len', type=int, default=MIN_STRING_LENGTH,
              help=f'Minimum string length to extract (default: {MIN_STRING_LENGTH}).')
@click.option('--max-len', type=int, default=MAX_STRING_LENGTH,
              help=f'Maximum string length to extract (default: {MAX_STRING_LENGTH}).')
@click.option('--top-count', type=int, default=TOP_STRINGS_COUNT,
              help=f'Number of top-scoring strings to include in the rule (default: {TOP_STRINGS_COUNT}).')
@click.option('--condition', '-c', default=DEFAULT_RULE_CONDITION,
              help=f'Condition for the YARA rule (e.g., "all of them", "any of them", "5 of them") (default: "{DEFAULT_RULE_CONDITION}").')
def generate(badware_dir, goodware_dir, rule_name, output_file, min_len, max_len, top_count, condition):
    """
    Generates a YARA rule by analyzing files in BADWARE_DIR and GOODWARE_DIR.

    BADWARE_DIR: Path to the directory containing malware samples.
    """
    yr_logger.info(f"[*] Starting YARA rule generation for badware in '{badware_dir}'...")

    try:
        # 1. Score strings
        scored_strings = score_strings(badware_dir, goodware_dir, min_len, max_len)

        if not scored_strings:
            click.echo("No significant strings found to generate a meaningful YARA rule. Exiting.")
            yr_logger.warning("[*] No significant strings found. YARA rule generation aborted.")
            sys.exit(0)

        # 2. Select top strings
        top_strings = [s for s, score in scored_strings[:top_count]]
        yr_logger.info(f"[*] Selected top {len(top_strings)} strings for rule generation.")

        # 3. Generate YARA rule
        generated_rule = generate_yara_rule(rule_name, top_strings, condition, output_file)
        click.echo(f"[+] YARA rule '{rule_name}' generated and saved to {output_file}")

    except FileNotFoundError as e:
        yr_logger.error(f"[ERROR] File or directory not found: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        yr_logger.critical(f"[CRITICAL] An unexpected error occurred during YARA rule generation: {e}")
        click.echo(f"An unexpected error occurred: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli()
