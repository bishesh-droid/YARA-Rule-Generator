# Yara Rule Generator

This project implements a command-line interface (CLI) tool that automates the generation of YARA rules. It helps malware researchers and security analysts create effective rules by analyzing a set of malware samples (badware) and optionally a set of clean files (goodware). The tool extracts and scores unique strings, then constructs a YARA rule based on the most indicative patterns.

## Features

-   **String Extraction:** Extracts printable ASCII and Unicode strings from binary files.
-   **Intelligent String Scoring:** Scores extracted strings based on their frequency and uniqueness across badware and goodware samples, prioritizing strings most indicative of malware.
-   **Automated Rule Generation:** Creates a YARA rule (`.yar` file) with a configurable rule name, meta-information, and a condition based on the top-scoring strings.
-   **Configurable Parameters:** Allows customization of minimum/maximum string lengths, number of top strings to include, and the logical condition for the YARA rule.
-   **File System Traversal:** Recursively processes files within specified badware and goodware directories.
-   **Logging:** Records all activities during string extraction, scoring, and rule generation.

## Project Structure

```
.
├── yara_generator/
│   ├── __init__.py        # Package initialization
│   ├── cli.py             # Command-line interface using Click
│   ├── extractor.py       # Logic for extracting strings from files
│   ├── scorer.py          # Logic for scoring strings based on frequency
│   ├── generator.py       # Logic for generating the YARA rule file
│   ├── logger.py          # Configures logging for the tool
│   └── config.py          # Configuration for string length, scoring, etc.
├── samples/
│   ├── goodware/          # Directory to place clean (non-malicious) files
│   └── badware/           # Directory to place malware samples
├── rules/
│   └── generated_rule.yar # (Generated) Example YARA rule file
├── logs/
│   └── yara_generator.log # Log file for tool activities
├── tests/
│   ├── __init__.py
│   └── test_generator.py  # Unit tests for extractor, scorer, and generator logic
├── .env.example           # Example environment variables
├── .gitignore
├── conceptual_analysis.txt
├── README.md
└── requirements.txt
```

## Prerequisites

-   Python 3.7+
-   `pip` for installing dependencies

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/Yara-Rule-Generator.git
    cd Yara-Rule-Generator
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the YARA Rule Generator from the project root directory.

```bash
python -m yara_generator.cli
```

**Preparation:**

1.  **Populate `samples/badware/`:** Place the malware samples (from the same family or with similar characteristics) for which you want to generate a rule.
2.  **Populate `samples/goodware/` (Optional but Recommended):** Place a collection of legitimate, clean files. This helps the tool identify strings unique to the malware and reduce false positives.

**Command:**

-   **`generate`**: Generates a YARA rule.
    ```bash
    # Basic generation using badware samples only
    python -m yara_generator.cli generate samples/badware

    # Generation using both badware and goodware for better scoring
    python -m yara_generator.cli generate samples/badware -g samples/goodware

    # Generate with a custom rule name and output file
    python -m yara_generator.cli generate samples/badware -n MyCustomMalwareRule -o rules/my_custom_rule.yar

    # Generate with a specific condition (e.g., 3 out of 5 strings must match)
    python -m yara_generator.cli generate samples/badware -g samples/goodware --top-count 5 --condition "3 of them"
    ```

**Important Notes:**

-   **Malware Handling:** Always handle malware samples in a secure and isolated environment (e.g., a virtual machine).
-   **Rule Quality:** Automatically generated rules are a starting point. Always review and test them with a YARA scanner (e.g., `yara -r rules/generated_rule.yar /path/to/scan`) to ensure accuracy and minimize false positives/negatives.

## Ethical Considerations

-   **Malware Handling:** This tool is designed to work with malware samples. Exercise extreme caution and ensure you are operating in a safe, isolated environment.
-   **Educational Purpose:** This tool is for educational and research purposes only. It helps in understanding malware analysis techniques and YARA rule creation.

## Testing

To run the automated tests, execute the following command from the project's root directory:

```bash
python -m unittest discover tests
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.