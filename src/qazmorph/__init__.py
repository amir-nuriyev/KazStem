"""Public API for qazmorph."""

from .analyzer import Analyzer
from .backend import BackendError
from .fixlist import FixlistError
from .generator import GenerationResult
from .types import Analysis, AnalysisSpan, Document, Morpheme, Token

__all__ = [
    "Analysis",
    "AnalysisSpan",
    "Analyzer",
    "BackendError",
    "Document",
    "FixlistError",
    "GenerationResult",
    "Morpheme",
    "Token",
]
__version__ = "0.2.3"
