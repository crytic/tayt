from setuptools import setup, find_packages

setup(
    name="fuzzstark",
    version="0.1",
    description="Fuzzstark is a fuzzer for the Cairo programming language.",
    author="Trail of Bits",
    license="AGPL-3.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "fuzzstark = fuzzstark.__main__:main",
        ]
    },
)
