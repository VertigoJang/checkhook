"""Write finished flows to rotating CSV files (ML training data).

Used by checkhookd where tcpdump/checkhook-capture isn't available (Windows): the
same nfstream statistical features the model uses, plus addressing columns so
ml.make_dataset can label the rows later. No payload is ever stored.

Files: <dir>/flows-YYYYmmdd-HHMMSS.csv, a new file every `rows_per_file` flows,
only the newest `keep` files are kept.
"""
import csv
import glob
import os
import time

from checkhook.features import FEATURES

META = ["ts_ms", "src_ip", "src_port", "dst_ip", "dst_port", "protocol"]


class FlowLogger:
    def __init__(self, directory, rows_per_file=50000, keep=40):
        self.dir, self.rows_per_file, self.keep = directory, rows_per_file, keep
        os.makedirs(directory, exist_ok=True)
        self._f = self._w = None
        self._rows = 0

    def _open(self):
        self.close()
        name = time.strftime("flows-%Y%m%d-%H%M%S.csv")
        path = os.path.join(self.dir, name)
        n = 1
        while os.path.exists(path):                 # several files in one second
            path = os.path.join(self.dir, f"{name[:-4]}-{n}.csv"); n += 1
        self._f = open(path, "w", newline="", encoding="utf-8")
        self._w = csv.writer(self._f)
        self._w.writerow(META + FEATURES)
        self._rows = 0
        for old in sorted(glob.glob(os.path.join(self.dir, "flows-*.csv")))[:-self.keep]:
            try:
                os.unlink(old)
            except OSError:
                pass

    def write(self, flow):
        if self._w is None or self._rows >= self.rows_per_file:
            self._open()
        row = [getattr(flow, "bidirectional_first_seen_ms", 0), flow.src_ip,
               getattr(flow, "src_port", 0), flow.dst_ip, getattr(flow, "dst_port", 0),
               getattr(flow, "protocol", 0)]
        row += [getattr(flow, f, 0) or 0 for f in FEATURES]
        self._w.writerow(row)
        self._rows += 1
        if self._rows % 100 == 0:
            self._f.flush()

    def close(self):
        if self._f:
            self._f.close()
            self._f = self._w = None
