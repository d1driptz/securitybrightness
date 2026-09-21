"""Analysis-only supplied-content API; no file acquisition or authority access."""

from .text_analysis import AnalysisResult, analyze_bytes

__all__ = ["AnalysisResult", "analyze_bytes"]
