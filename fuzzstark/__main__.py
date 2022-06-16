"""
Main module
"""

import asyncio
import fuzzstark.fuzzer


def main() -> None:
    """
    Main
    """

    asyncio.run(fuzzstark.fuzzer.main())


if __name__ == "__main__":
    main()
