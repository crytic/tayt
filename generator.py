import random
import sys
import logging
from typing import TYPE_CHECKING, List, Optional, Tuple
from starkware.starknet.services.api.contract_class import EntryPointType
from starkware.cairo.lang.cairo_constants import DEFAULT_PRIME
from starkware.cairo.lang.compiler.ast.cairo_types import (
    TypeFelt,
    TypePointer,
    TypeStruct,
    TypeTuple,
)

if TYPE_CHECKING:
    from fuzzer import Fuzzer, ExternalFunction


class TxGenerator:
    def __init__(self, fuzzer: "Fuzzer") -> None:
        self.fuzzer = fuzzer

    def generate_fuzzed_tx(self) -> Tuple[int, str, List[int], EntryPointType, Optional[int]]:
        """
        Generate fuzzed arguments to send a transaction
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

        if r >= 0.5 and r < 0.7:
            # positive values within range_check_builtin bound
            return random.randint(0, 2**128 - 1)

        if r >= 0.7 and r < 0.8:
            # positive values outside range_check_builtin bound
            return random.randint(2**128, DEFAULT_PRIME // 2 - 1)

        # negative values
        return random.randint(DEFAULT_PRIME // 2, DEFAULT_PRIME - 1)

    @staticmethod
    def _generate_array_length() -> int:
        return random.randint(1, 10)

    def _generate_fuzzed_abi_value(self, abi) -> List[int]:
        calldata: List[int] = []
        for arg_type in abi:
            self._generate_value(arg_type, calldata)
        return calldata

    def _generate_value(self, arg_type, calldata) -> None:
        """
        Generate a value depending on the argument type
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
            contract_struct = self.fuzzer.struct_manager.get_struct_definition(struct_name)
            for m in contract_struct.members.values():
                self._generate_value(m.cairo_type, calldata)

        else:
            logging.error(f"Unknown argument type {arg_type}")
            sys.exit(1)

    def _choose_function(self) -> "ExternalFunction":
        """
        Choose a random function to use in a transaction
        """

        return random.choice(self.fuzzer.external_functions)

    def _choose_sender(self) -> int:
        """
        Choose a random sender to use in a transaction
        """

        return random.choice(self.fuzzer.config.sender)
