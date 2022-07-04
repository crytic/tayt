"""
Module containing a FuzzerWorker
"""

from collections import namedtuple
from typing import TYPE_CHECKING
from starkware.starknet.testing.state import StarknetState

if TYPE_CHECKING:
    from fuzzer import Fuzzer


TxSequenceElement = namedtuple(
    "TxSequenceElement",
    ["sender", "function_name", "arguments", "entry_point_type", "nonce", "events_emitted"],
)

# pylint: disable=too-few-public-methods
class FuzzerWorker:
    """
    Base class to inherit when implementing a fuzzer worker mode
    """

    def __init__(self, fuzzer: "Fuzzer", worker_index: int):
        """
        Init the object

        Args:
            fuzzer (Fuzzer): Fuzzer instance
            worker_index: Worker index of this instance
        """

        self.fuzzer = fuzzer
        self.worker_index = worker_index
        # State refresh every run
        self.state: StarknetState = None

    async def fuzz(self) -> None:
        """
        Methid to start fuzzing, should be implemented in the derived class
        """
