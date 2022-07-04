"""
Module containig a FuzzerWorkerException
"""

import logging
from typing import List, Optional, Tuple
from starkware.starkware_utils.error_handling import StarkException
from tayt.workers.fuzzer_worker_base import FuzzerWorker, TxSequenceElement


class AssertionException(Exception):
    """
    Exception to raise in hints when eception mode enabled
    """


# pylint: disable=too-few-public-methods, protected-access
class FuzzerWorkerException(FuzzerWorker):
    """
    Execute the transactions and check for possible AssertionException raised
    """

    async def fuzz(self) -> None:
        """
        Start fuzzing
        """

        while 1:
            if len(self.fuzzer.assertion_exception) == 0:
                break

            transactions, message = await self._test_tx_sequence()

            if transactions is not None:
                if not self.fuzzer.config.no_shrink:
                    transactions = await self._shrink_tx_sequence(transactions, message)
                logging.info(f"[!] {message} violated")
                logging.info("Call sequence:")

                for t in transactions:
                    logging.info(f"\t{t.function_name}{t.arguments} from {t.sender}")
                    for event in t.events_emitted:
                        logging.info(
                            f"\t E {self.fuzzer.event_manager._get_event_name(event.keys[0])}{event.data}"
                        )

    async def _test_tx_sequence(
        self,
    ) -> Tuple[Optional[List[TxSequenceElement]], Optional[str]]:
        """
        Test a sequence of transactions and returns the AssertionException message raised with the sequence of transactions

        Returns:
            Tuple[Optional[List[TxSequenceElement]], Optional[str]: (sequence of transactions, exception raised)
        """

        # Reset the state when testing a new sequence
        self.state = self.fuzzer.state.copy()

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

                self.fuzzer.coverage.update(execution_info.call_info.pc)

            except StarkException as e:
                # Last line of exception contains our AssertionException if it was raised
                last_line = e.message.split("\n")[-1]
                if last_line.startswith("tayt.workers.fuzzer_worker_exception.AssertionException"):
                    transactions.append(
                        TxSequenceElement(
                            sender,
                            function_name,
                            arguments,
                            entry_point_type,
                            nonce,
                            [],
                        )
                    )
                    message = last_line.split(": ")[1]

                    for exception_message in self.fuzzer.assertion_exception:
                        if message.startswith(exception_message):
                            # We remove the assertion exception message violated from this sequence
                            self.fuzzer.assertion_exception.remove(exception_message)
                            return transactions, message

        return None, None

    async def _shrink_tx_sequence(
        self, transactions: List[TxSequenceElement], exception_message: Optional[str]
    ) -> List[TxSequenceElement]:
        """
        Attempts to shrink the provided transaction sequence by removing redundant transactions

        Args:
            transactions (List[TxSequenceElement]): Provided sequence of transactions
            exception_message (Optional[str]): Message in the AssertionException raised

        Returns:
            List[TxSequenceElement]: The optimized sequence of transactions
        """

        shrinked_sequence: List[TxSequenceElement] = transactions

        i = 0
        while i < len(shrinked_sequence):
            # Create a sequence without the item at index i
            test_sequence: List[TxSequenceElement] = (
                shrinked_sequence[:i] + shrinked_sequence[i + 1 :]
            )

            # Reset the state when testing a new sequence
            self.state = self.fuzzer.state.copy()

            # Track if an AssertionException was raised
            exception = False

            for transaction in test_sequence:
                try:
                    await self.state.invoke_raw(
                        self.fuzzer.deployed_contract_address,
                        transaction.function_name,
                        transaction.arguments,
                        transaction.sender,
                        0,
                        entry_point_type=transaction.entry_point_type,
                        nonce=transaction.nonce,
                    )
                except StarkException as e:
                    last_line = e.message.split("\n")[-1]
                    if last_line.startswith(
                        "tayt.workers.fuzzer_worker_exception.AssertionException"
                    ):
                        message = last_line.split(": ")[1]
                        if message == exception_message:
                            exception = True
                            shrinked_sequence = test_sequence
                            break

            # If an AssertionException is raised remove in the next iteration the same index
            # since the item at that index will be new
            if not exception:
                i += 1

        return shrinked_sequence
