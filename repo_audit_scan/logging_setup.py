"""Structured logging setup for repo-audit-scan."""
import logging
import logging.handlers
import sys
from typing import Optional
from pathlib import Path


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    verbose: bool = False,
) -> logging.Logger:
    """Set up structured logging for the application.
    
    Args:
        level: Logging level
        log_file: Optional file path for logging
        verbose: Enable verbose logging
        
    Returns:
        Configured logger instance
    """
    if verbose:
        level = logging.DEBUG
    
    logger = logging.getLogger("repo_audit_scan")
    logger.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance by name.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(f"repo_audit_scan.{name}")
