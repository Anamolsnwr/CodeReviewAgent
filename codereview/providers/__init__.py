"""AI providers package init."""

from codereview.providers.base import BaseAIProvider
from codereview.providers.mock_provider import MockAIProvider

__all__ = ["BaseAIProvider", "MockAIProvider"]

try:
    from codereview.providers.groq_provider import GroqAIProvider
    __all__.append("GroqAIProvider")
except ImportError:
    pass
