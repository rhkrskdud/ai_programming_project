import csv
from pathlib import Path
from typing import Iterable

from .features import CSV_COLUMNS


class CsvWriter:
    def __init__(self, path: Path):
        self.path = path
        self._fh = None
        self._writer = None

    def __enter__(self):
        self._fh = self.path.open("w", encoding="utf-8", newline="")
        self._writer = csv.DictWriter(self._fh, fieldnames=CSV_COLUMNS)
        self._writer.writeheader()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._fh is not None:
            self._fh.close()

    def write_row(self, row: dict) -> None:
        self._writer.writerow({col: row.get(col, 0) for col in CSV_COLUMNS})

    def write_rows(self, rows: Iterable[dict]) -> None:
        for row in rows:
            self.write_row(row)
