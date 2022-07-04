"""
Fuzzer main module
"""

from collections import namedtuple
import os
import sys
import argparse
import logging
import time
import signal
import re
from typing import Dict, List, Set
from starkware.starknet.compiler.compile import compile_starknet_files
from starkware.starknet.services.api.contract_class import ContractClass
from starkware.starknet.testing.state import StarknetState
from starkware.starknet.testing.contract_utils import parse_arguments, StructManager, EventManager
from starkware.starkware_utils.error_handling import StarkException
from tayt.generator import TxGenerator
from tayt.hooking import hook
from tayt.workers.fuzzer_worker_property import FuzzerWorkerProperty
from tayt.workers.fuzzer_worker_exception import FuzzerWorkerException
from tayt.workers.fuzzer_worker_base import FuzzerWorker

ExternalFunction = namedtuple("ExternalFunction", ["name", "arguments_type", "type"])
FuzzerConfig = namedtuple(
    "FuzzerConfig",
    [
        "filename",
        "psender",
        "sender",
        "blacklist_function",
        "seq_len",
        "cairo_path",
        "coverage",
        "no_shrink",
        "exception_mode",
    ],
)

logging.basicConfig(level=logging.INFO, format="%(message)s")

# pylint: disable=too-many-instance-attributes
class Fuzzer:
    """
    Fuzzer class, set up the fuzzer environment
    """

    def __init__(self, args) -> None:  # type: ignore
        """
        Init the object

        Args:
            args: Command line options
        """

        filename = args.filename

        if not os.path.isabs(filename):
            filename = os.path.join(os.getcwd(), filename)

        # We add the constructor, and fallback functions as blacklist
        # For now we don't fuzz fallback functions
        blacklist_function = set(
            ["constructor", "__default__", "__l1__default__"] + args.blacklist_function
        )
        self.config: FuzzerConfig = FuzzerConfig(
            filename,
            args.psender,
            args.sender,
            blacklist_function,
            args.seq_len,
            args.cairo_path,
            args.coverage,
            args.no_shrink,
            args.exception_mode,
        )
        self.generator = TxGenerator(self)
        self.workers: List[FuzzerWorker] = []
        self.state: StarknetState = None
        # List of contract functions name that represent properties to be tested
        # Read only functions that start with fuzz_ and return one felt variable
        # The functions return 1 if the property is not violated otherwise 0
        self.property_functions: List[str] = []
        # List of exception messages when an assertion fails
        self.assertion_exception: List[str] = []
        # List of contract functions that change contract state
        # These are the functions to create a sequence of transactions to test
        self.external_functions: List[ExternalFunction] = []
        self.deployed_contract_address: int
        self.contract_class: ContractClass
        # TODO we could avoid these two helper class and do it manually
        self.struct_manager: StructManager = None
        self.event_manager: EventManager = None
        # For now we only keep track of the PCs executed
        self.coverage: Set[int] = set()

    async def start(self) -> None:
        """
        Start the fuzzer
        """

        hook()
        signal.signal(signal.SIGINT, self.handler_output_coverage)

        self.contract_class = compile_starknet_files(
            [self.config.filename],
            cairo_path=self.config.cairo_path,
            disable_hint_validation=True,
            debug_info=True,
        )

        if self.contract_class.abi is not None:
            await self._deploy()
        else:
            logging.error("No abi generated.")
            sys.exit(1)

        if self.config.exception_mode:
            self.workers.append(FuzzerWorkerException(self, 1))
        else:
            self.workers.append(FuzzerWorkerProperty(self, 1))

        await self.workers[0].fuzz()

        if not self.config.exception_mode and len(self.property_functions) == 0:
            logging.info("All properties have been violated")
        elif len(self.assertion_exception) == 0:
            logging.info("All assertion exception have been violated")

        self.output_coverage()

    async def _deploy(self) -> None:
        """
        Deploy the contract under test and parse the abi to get properties and external functions
        """

        for item in self.contract_class.abi:
            if item["type"] == "constructor":
                if len(item["inputs"]) != 0:
                    logging.error("Constructor with arguments not supported.")
                    sys.exit(1)
                break

        self.struct_manager = StructManager(self.contract_class.abi)
        self.event_manager = EventManager(self.contract_class.abi)
        self.state = await StarknetState.empty()

        try:
            deployed_contract_address, _ = await self.state.deploy(
                contract_class=self.contract_class, constructor_calldata=[]
            )
            self.deployed_contract_address = deployed_contract_address
        except StarkException as e:
            logging.error(
                f"Constructor raised an exception. \nCode: {e.code} \nMessage: {e.message}"
            )
            sys.exit(1)

        self._get_property_and_external_functions()

        if not self.config.exception_mode:
            logging.info("Fuzzing the following properties:")
            for property_function in self.property_functions:
                logging.info(f"\t{property_function}")
        else:
            self._get_assertion_exceptions()

        logging.info("External functions:")
        for external_function in self.external_functions:
            logging.info(f"\t{external_function.name}")

    def output_coverage(self) -> None:
        """
        Output coverage to a file
        """

        if not self.config.coverage:
            return

        file_to_code: Dict[str, List[str]] = {}

        for pc in self.coverage:
            all_locations = self.contract_class.program.debug_info.instruction_locations[
                pc
            ].get_all_locations()
            all_locations_parsed = [
                (i.input_file.filename, i.start_line, i.end_line) for i in all_locations
            ]

            for l in all_locations_parsed:
                filename = l[0]

                if filename not in file_to_code:
                    if filename.startswith("autogen/"):
                        continue
                    with open(filename, "r", encoding="utf8") as f:
                        file_to_code[filename] = f.readlines()

                coverage_code = file_to_code[filename]
                for line in range(l[1] - 1, l[2]):
                    if not coverage_code[line].startswith("*"):
                        coverage_code[line] = f"*{coverage_code[line]}"

        with open(f"covered.{int(time.time())}.txt", "w", encoding="utf8") as f:
            logging.info(f"Coverage in {f.name}")
            for filename, code in file_to_code.items():
                f.write(f"\n{filename}\n")
                f.write("".join(code))

    def handler_output_coverage(self, signum, frame) -> None:  # type: ignore # pylint: disable=unused-argument
        """
        Handler for signal.SIGINT to output the coverage file

        Args:
            signum: Not used
            frame: Not used
        """

        self.output_coverage()
        sys.exit(1)

    def _get_property_and_external_functions(self) -> None:
        for item in self.contract_class.abi:
            if (
                not self.config.exception_mode
                and item["name"].startswith("fuzz_")
                and item["type"] == "function"
            ):
                if (
                    len(item["inputs"]) == 0
                    and item.get("stateMutability") == "view"
                    and len(item["outputs"]) == 1
                    and item["outputs"][0]["type"] == "felt"
                ):
                    self.property_functions.append(item["name"])
                else:
                    logging.warning(
                        f"Function {item['name']} starts with fuzz_ but doesn't respect the criteria. It won't be used as a property."
                    )
            elif (
                item.get("stateMutability") is None
                and item["name"] not in self.config.blacklist_function
                and item["type"] in ("function", "l1_handler")
            ):
                _, cairoTypes = parse_arguments(item["inputs"])
                self.external_functions.append(
                    ExternalFunction(item["name"], cairoTypes, item["type"])
                )

        assert len(self.external_functions) > 0

    def _get_assertion_exceptions(self) -> None:
        # We get all the possibe AssertionException messages
        logging.info("Fuzzing the following assertion exceptions:")
        for hints in self.contract_class.program.hints.values():
            # pylint: disable=anomalous-backslash-in-string
            exceptions_hints = [
                re.findall('raise AssertionException\([\s"a-zA-Z0-9{}\.]*\)', i.code) for i in hints
            ]
            for exceptions_hint in exceptions_hints:
                for exception in exceptions_hint:
                    start_message = exception.find('"')
                    start_variable = exception.find("{")
                    if start_message != -1 and start_variable != -1:
                        message = exception[start_message + 1 : start_variable]
                        self.assertion_exception.append(message)
                        logging.info(f"\t{message}")
                    else:
                        message = exception[start_message + 1 : -2]
                        self.assertion_exception.append(message)
                        logging.info(f"\t{message}")


async def main() -> None:
    """
    Parse cli options and start the fuzzer
    """

    parser = argparse.ArgumentParser(description="StarkNet smart contract fuzzer.")
    parser.add_argument("filename", type=str, help="Cairo file to analyze.")
    parser.add_argument(
        "--seq-len",
        type=int,
        help="Number of transactions to generate during testing. (default: 10)",
        default=10,
    )
    parser.add_argument(
        "--blacklist-function",
        type=str,
        help="Function name (space separated) to blacklist from execution.",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "--psender",
        type=int,
        help="Address of the sender for property transactions. (default: 1)",
        default=1,
    )
    parser.add_argument(
        "--sender",
        type=int,
        help="Addresses (space separated) to use for the transactions sent during testing. (default: [0, 1, 2])",
        nargs="+",
        default=[0, 1, 2],
    )
    parser.add_argument(
        "--cairo-path",
        type=str,
        help="A list of directories, separated by space to resolve import paths.",
        nargs="+",
        default=[],
    )
    parser.add_argument("--coverage", action="store_true", help="Output a coverage file.")
    parser.add_argument(
        "--no-shrink", action="store_true", help="Avoid shrinking failing sequences."
    )
    parser.add_argument("--exception-mode", action="store_true", help="Enable exception mode.")

    args = parser.parse_args()

    fuzzer = Fuzzer(args)
    await fuzzer.start()
