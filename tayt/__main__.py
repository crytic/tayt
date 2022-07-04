"""
Main module
"""

import asyncio
import tayt.fuzzer


def main() -> None:
    """
    Main
    """

    asyncio.run(tayt.fuzzer.main())


if __name__ == "__main__":
    main()
