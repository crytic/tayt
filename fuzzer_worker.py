from collections import namedtuple
import logging
from typing import TYPE_CHECKING, Any, List, Optional, Tuple
from starkware.starknet.testing.state import StarknetState
from starkware.starkware_utils.error_handling import StarkException

if TYPE_CHECKING:
    from fuzzer import Fuzzer


TxSequenceElement = namedtuple(
    "TxSequenceElement",
    ["sender", "function_name", "arguments", "entry_point_type", "nonce", "events_emitted"],
)


class FuzzerWorker:
    def __init__(self, fuzzer: "Fuzzer", worker_index: int):
        self.fuzzer = fuzzer
        self.worker_index = worker_index
        # State refresh every run
        self.state: StarknetState = None

    async def fuzz(self):
        while 1:
            if len(self.fuzzer.property_functions) == 0:
                break

            self.state = self.fuzzer.state.copy()
            transactions, violated = await self._test_tx_sequence()

            if transactions is not None:
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

    async def _check_violated_property_tests(self) -> List[Tuple[str, Any]]:
        violated = []

        for property_function in self.fuzzer.property_functions:
            # We assume that property functions don't raise exceptions so no try/except
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
    ) -> Tuple[Optional[List[TxSequenceElement]], Optional[List[Tuple[str, Any]]]]:
        """
        Test a sequence of transactions and returns if some properties are violated
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
