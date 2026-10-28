"""agent-blackbox: a tamper-evident flight recorder for LLM agents."""

from .diff import diff_runs
from .ledger import Ledger, verify_events
from .privacy import Pseudonymiser
from .recorder import Cassette, Recorder, ReplayMismatch

__version__ = "0.1.0"
__all__ = ["Cassette", "Ledger", "Pseudonymiser", "Recorder", "ReplayMismatch", "diff_runs", "verify_events", "__version__"]
