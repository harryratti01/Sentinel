"""Windows-compatible directory watching, isolated from persistence and CLI concerns."""

from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .events import normalize_event


class WatcherError(Exception):
    """Raised when a requested directory cannot be monitored."""


EventSink = Callable[[dict[str, object]], None]


class _SentinelEventHandler(FileSystemEventHandler):
    def __init__(self, event_sink: EventSink) -> None:
        self.event_sink = event_sink

    def on_created(self, event: FileSystemEvent) -> None:
        self.event_sink(normalize_event("CREATED", event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        self.event_sink(normalize_event("MODIFIED", event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        self.event_sink(normalize_event("DELETED", event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        self.event_sink(
            normalize_event(
                "MOVED",
                event.dest_path,
                old_path=event.src_path,
                new_path=event.dest_path,
            )
        )


def watch_directory(directory: str | Path, event_sink: EventSink) -> None:
    """Watch one directory (including its children) until Ctrl+C is pressed."""
    path = Path(directory).expanduser()
    if not path.is_dir():
        raise WatcherError(f"Directory not found: {path}")

    observer = Observer()
    observer.schedule(_SentinelEventHandler(event_sink), str(path.resolve()), recursive=True)
    observer.start()
    try:
        while True:
            observer.join(1)
    except KeyboardInterrupt:
        print("Stopping Sentinel monitoring.")
    finally:
        observer.stop()
        observer.join()
