import io
import logging
from abc import ABCMeta, abstractmethod
from pathlib import Path


from logalyzer.logs import LogEntry


# --------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------


class LogEntryAnalyzer(metaclass=ABCMeta):
    @abstractmethod
    def process(self, log_entry: LogEntry): ...

    def onNewFile(self, file: Path): ...


class Reportable(metaclass=ABCMeta):
    @abstractmethod
    def report(self, /, stream: io.TextIOBase | None = None, **kwargs): ...


# --------------------------------------------------------------------------

