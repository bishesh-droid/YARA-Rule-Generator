# yara_generator/logger.py

import logging
import os
from .config import LOG_FILE, LOG_DIR, VERBOSE_CONSOLE_OUTPUT

# Get the logger instance
yr_logger = logging.getLogger('yara_generator')

def setup_logging():
    """
    Configures logging for the YARA Rule Generator.
    Logs to a file and optionally to the console.
    This function should be called once at the beginning of the application.
    """
    # Prevent adding handlers multiple times
    if yr_logger.hasHandlers():
        return

    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    yr_logger.setLevel(logging.DEBUG)
    yr_logger.propagate = False  # Prevent messages from being passed to the root logger

    # File handler
    file_handler = logging.FileHandler(LOG_FILE, mode='a')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    yr_logger.addHandler(file_handler)

    # Console handler (optional)
    if VERBOSE_CONSOLE_OUTPUT:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
        yr_logger.addHandler(console_handler)

# Initialize logging when the module is imported for the first time
setup_logging()
