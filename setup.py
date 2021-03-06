from setuptools import setup, find_packages

setup(
    name="tayt",
    version="0.1",
    description="Tayt is a fuzzer for StarkNet smart contract written in Cairo.",
    author="Trail of Bits",
    license="AGPL-3.0",
    packages=find_packages(),
    install_requires=["cairo-lang>=0.9.0"],
    entry_points={
        "console_scripts": [
            "tayt = tayt.__main__:main",
        ]
    },
)
