import json
import os

from filelock import FileLock

"""
The IV service is responsible for generating and storing an IV counter. It is used to generate unique IVs for each message that is sent.
This means that the IV counter must return a unique number each time. We do this by "reserving" a block of counters that can be used.
Once we hit the low water mark for that block, we reserve a new block and store the new low water mark. This way, we can never (?) use
a duplicate counter, but we can miss counters in case of a crash. That is not a problem though.

Note we don't case about thread safety here, as we assume that the IV service is only used by one thread at a time.


Counter     Low Water Mark
--------------------------
  100         95
  99          95
  98          95
  97          95
  96          95

 Here we hit the low water mark, so we reserve a new block and store the LWM to disk
 
  95          90
  94          90
  ...
"""

class IvError(Exception):
    pass

class IvService:
    def __init__(self, filename="iv.json", block_size = 100) -> None:
        self.filename = filename
        self.block_size = block_size

        try:
            self.remaining = self.low_watermark = self.load_counter()
        except IvError:
            self.remaining = self.low_watermark = 0

    def set_iv_counter(self, counter: int, if_not_exists: bool = True) -> None:
        """
        Manually set the IV counter.
        """
        if if_not_exists and os.path.exists(self.filename):
            return
        self.store_counter(counter)
        self.low_watermark = self.remaining = counter

    def get_iv_counter(self) -> int:
        """
        Return the current IV counter
        """
        if self.remaining <= self.low_watermark:
            self.low_watermark -= self.block_size
            self.store_counter(self.low_watermark)

        self.remaining -= 1
        return self.remaining

    def load_counter(self) -> int:
        """
        Load counter from disk
        """
        try:
            lock = FileLock(self.filename + ".lock", timeout=1)
            with lock:
                with open(self.filename, 'r') as f:
                    data = json.load(f)
                    return data['remaining']
        except Exception as e:
            raise IvError(e)

    def store_counter(self, counter: int) -> None:
        """
        Store counter to disk
        """
        try:
            lock = FileLock(self.filename + ".lock", timeout=1)
            with lock:
                with open(self.filename, 'w') as f:
                    json.dump({'remaining': counter}, f)
        except Exception as e:
            raise IvError(e)

