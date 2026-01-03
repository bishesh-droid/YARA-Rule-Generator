# yara_generator/logger.py

import logging
import os
from .config import LOG_FILE, LOG_DIR, VERBOSE_CONSOLE_OUTPUT

def setup_logging():
    """
    Configures logging for the YARA Rule Generator.
    Logs to a file and optionally to the console.
    """
    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    # Create a logger
    yr_logger = logging.getLogger('yara_generator')
    yr_logger.setLevel(logging.INFO)
    yr_logger.propagate = False # Prevent messages from being passed to the root logger

    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    yr_logger.addHandler(file_handler)

    # Console handler (optional)
    if VERBOSE_CONSOLE_OUTPUT:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
        yr_logger.addHandler(console_handler)

    return yr_logger

# Initialize logger when module is imported
yr_logger = setup_logging()
