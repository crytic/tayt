"""
Helper module to generate a fuzzed transaction
"""

import random
import sys
import logging
from typing import TYPE_CHECKING, List, Optional, Tuple
from starkware.starknet.services.api.contract_class import EntryPointType
from starkware.cairo.lang.cairo_constants import DEFAULT_PRIME
from starkware.cairo.lang.compiler.ast.cairo_types import (
    CairoType,
    TypeFelt,
    TypePointer,
    TypeStruct,
    TypeTuple,
)

if TYPE_CHECKING:
    from fuzzer import Fuzzer, ExternalFunction

# pylint: disable=too-few-public-methods
class TxGenerator:
    """
    Generate fuzzed transaction's fields and arguments
    """

    def __init__(self, fuzzer: "Fuzzer") -> None:
        """
        Init the object

        Args:
            fuzzer: Fuzzer instance
        """

        self.fuzzer = fuzzer

    def generate_fuzzed_tx(self) -> Tuple[int, str, List[int], EntryPointType, Optional[int]]:
        """
        Return a Tuple of transaction's fields and arguments

        Returns:
            Tuple[int, str, List[int], EntryPointType, Optional[int]]: Tuple of data to use in a transaction
        """

        selected_sender = self._choose_sender()
        selected_function = self._choose_function()
        selected_arguments = self._generate_fuzzed_abi_value(selected_function.arguments_type)
        if selected_function.type == "function":
            entry_point_type = EntryPointType.EXTERNAL
            nonce = None
        else:
            entry_point_type = EntryPointType.L1_HANDLER
            # TODO check valid range
            nonce = random.randint(2**128, 2**250)

        return selected_sender, selected_function.name, selected_arguments, entry_point_type, nonce

    @staticmethod
    def _generate_int() -> int:
        """
        Generate a random int

        Returns:
            int: Value generated
        """

        r = random.random()
        # 50% probability to generate an edge case value
        if r < 0.5:
            return random.choice(
                [
                    random.randint(0, 2),
                    # Values around range_check_builtin bound
                    random.randint(2**128 - 1, 2**128 + 1),
                    # Negative values [-1, -3]
                    random.randint(DEFAULT_PRIME - 3, DEFAULT_PRIME - 1),
                ]
            )

        if 0.5 <= r < 0.7:
            # positive values within range_check_builtin bound
            return random.randint(0, 2**128 - 1)

        if 0.7 <= r < 0.8:
            # positive values outside range_check_builtin bound
            return random.randint(2**128, DEFAULT_PRIME // 2 - 1)

        # negative values
        return random.randint(DEFAULT_PRIME // 2, DEFAULT_PRIME - 1)

    @staticmethod
    def _generate_array_length() -> int:
        """
        Generate an array length

        Returns:
            int: Array length
        """

        return random.randint(1, 10)

    def _generate_fuzzed_abi_value(self, abi: List[CairoType]) -> List[int]:
        """
        Generate a list of arguments depending on the abi paramter

        Args:
            abi (List[CairoType]): List of CairoType representing a function's abi

        Returns:
            List[int]: The generated list of arguments
        """

        calldata: List[int] = []
        for arg_type in abi:
            self._generate_value(arg_type, calldata)
        return calldata

    def _generate_value(self, arg_type: CairoType, calldata: List[int]) -> None:
        """
        Generate a value depending on the argument type

        Args:
            arg_type (CairoType): Type for which we have to generate a value
            calldata (List[int]): List to which the generated value will be appended
        """

        if isinstance(arg_type, TypeFelt):
            calldata.append(TxGenerator._generate_int())

        elif isinstance(arg_type, TypePointer):
            length = TxGenerator._generate_array_length()
            calldata.append(length)
            for _ in range(length):
                self._generate_value(arg_type.pointee, calldata)

        elif isinstance(arg_type, TypeTuple):
            for t in arg_type.types:
                self._generate_value(t, calldata)

        elif isinstance(arg_type, TypeStruct):
            # We can have specific input generation strategies for known struct
            # e.g. Uint256
            struct_name = arg_type.scope.path[-1]
            contract_struct = self.fuzzer.struct_definition[struct_name]
            for m in contract_struct.members.values():
                self._generate_value(m.cairo_type, calldata)

        else:
            logging.error(f"Unknown argument type {arg_type}")
            sys.exit(1)

    def _choose_function(self) -> "ExternalFunction":
        """
        Choose a random function to use in a transaction

        Returns:
            ExternalFunction: External function to use in the transaction
        """

        return random.choice(self.fuzzer.external_functions)

    def _choose_sender(self) -> int:
        """
        Choose a random sender to use in a transaction

        returns:
            int: Sender to use in the transaction
        """

        return random.choice(self.fuzzer.config.sender)
