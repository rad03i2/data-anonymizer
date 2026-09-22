"""Local policy-driven data anonymization."""

from .core import AnonymizationError, Report, anonymize_file, anonymize_records, load_policy

__all__ = ["AnonymizationError", "Report", "anonymize_file", "anonymize_records", "load_policy"]
__version__ = "1.0.0"
