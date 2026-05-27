"""Configuration loading and management."""
from pathlib import Path
from typing import Dict, Any, Optional
import yaml
from repo_audit_scan.models import ScanConfig
from repo_audit_scan.error import ConfigurationError


def load_config(config_path: Optional[str] = None) -> ScanConfig:
    """Load scan configuration from YAML file or environment.
    
    Args:
        config_path: Path to YAML config file
        
    Returns:
        ScanConfig object
        
    Raises:
        ConfigurationError: If config is invalid
    """
    if config_path:
        return load_config_from_file(config_path)
    else:
        return ScanConfig(repository_path=".")


def load_config_from_file(config_path: str) -> ScanConfig:
    """Load configuration from a YAML file.
    
    Args:
        config_path: Path to YAML config file
        
    Returns:
        ScanConfig object
        
    Raises:
        ConfigurationError: If file not found or invalid YAML
    """
    path = Path(config_path)
    if not path.exists():
        raise ConfigurationError(f"Config file not found: {config_path}")
    
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in config file: {e}")
    
    try:
        return ScanConfig.from_dict(data)
    except TypeError as e:
        raise ConfigurationError(f"Invalid config structure: {e}")


def validate_config(config: ScanConfig) -> bool:
    """Validate a ScanConfig object.
    
    Args:
        config: ScanConfig to validate
        
    Returns:
        True if valid
        
    Raises:
        ConfigurationError: If invalid
    """
    path = Path(config.repository_path)
    if not path.exists():
        raise ConfigurationError(f"Repository path does not exist: {config.repository_path}")
    
    if config.max_file_size <= 0:
        raise ConfigurationError("max_file_size must be positive")
    
    if config.max_files <= 0:
        raise ConfigurationError("max_files must be positive")
    
    return True
