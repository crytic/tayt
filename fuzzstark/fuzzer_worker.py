"""
Module containig a FuzzerWorker
"""

from collections import namedtuple
import logging
from typing import TYPE_CHECKING, List, Optional, Tuple
from starkware.starknet.testing.state import StarknetState
from starkware.starkware_utils.error_handling import StarkException
from starkware.starknet.business_logic.execution.objects import Event

if TYPE_CHECKING:
    from fuzzer import Fuzzer


TxSequenceElement = namedtuple(
    "TxSequenceElement",
    ["sender", "function_name", "arguments", "entry_point_type", "nonce", "events_emitted"],
)

# pylint: disable=too-few-public-methods, protected-access
class FuzzerWorker:
    """
    Execute the transactions and check for possible violated properties
    """

    def __init__(self, fuzzer: "Fuzzer", worker_index: int):
        self.fuzzer = fuzzer
        self.worker_index = worker_index
        # State refresh every run
        self.state: StarknetState = None

    async def fuzz(self) -> None:
        """
        Start fuzzing
        """

        while 1:
            if len(self.fuzzer.property_functions) == 0:
                break

            self.state = self.fuzzer.state.copy()
            transactions, violated = await self._test_tx_sequence()

            if transactions is not None and violated is not None:
                for property_violated in violated:
                    logging.info(f"[!] {property_violated[0]} violated")
                    for event in property_violated[1]:
                        logging.info(
                            f"\tE {self.fuzzer.event_manager._get_event_name(event.keys[0])}{event.data}"
                        )
                    logging.info("Call sequence:")

                for t in transactions:
                    logging.info(f"\t{t.function_name}{t.arguments} from {t.sender}")
                    for event in t.events_emitted:
                        logging.info(
                            f"\t E {self.fuzzer.event_manager._get_event_name(event.keys[0])}{event.data}"
                        )

    async def _check_violated_property_tests(self) -> List[Tuple[str, List[Event]]]:
        """
        Check for possible violated properties after every transaction

        Returns:
            List[Tuple[str, List[Event]]]: List of violated properties with emitted events
        """

        violated = []

        for property_function in self.fuzzer.property_functions:
            call_info = await self.state.call_raw(
                self.fuzzer.deployed_contract_address,
                property_function,
                [],
                self.fuzzer.config.psender,
                0,
            )

            self.fuzzer.coverage.update(call_info.pc)

            # Property violated
            if call_info.retdata == [0]:
                self.fuzzer.property_functions.remove(property_function)
                violated.append((property_function, call_info.get_sorted_events()))

        return violated

    async def _test_tx_sequence(
        self,
    ) -> Tuple[Optional[List[TxSequenceElement]], Optional[List[Tuple[str, List[Event]]]]]:
        """
        Test a sequence of transactions and returns the violated properties with the sequence of transactions

        Returns:
            Tuple[Optional[List[TxSequenceElement]], Optional[List[Tuple[str, List[Event]]]]]: (sequence of transactions, violated properties)
        """

        transactions: List[TxSequenceElement] = []

        for _ in range(self.fuzzer.config.seq_len):
            (
                sender,
                function_name,
                arguments,
                entry_point_type,
                nonce,
            ) = self.fuzzer.generator.generate_fuzzed_tx()
            try:
                execution_info = await self.state.invoke_raw(
                    self.fuzzer.deployed_contract_address,
                    function_name,
                    arguments,
                    sender,
                    0,
                    entry_point_type=entry_point_type,
                    nonce=nonce,
                )

                self.fuzzer.coverage.update(execution_info.call_info.pc)

                transactions.append(
                    TxSequenceElement(
                        sender,
                        function_name,
                        arguments,
                        entry_point_type,
                        nonce,
                        execution_info.call_info.get_sorted_events(),
                    )
                )
                violated = await self._check_violated_property_tests()
                if len(violated) > 0:
                    return transactions, violated
            except StarkException:
                continue

        return None, None
