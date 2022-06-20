# TBD

TBD is a StarkNet smart contract fuzzer.

## Installation

We recommend using a Python [`virtual environment`](https://docs.python.org/3/library/venv.html).
```bash
git clone https://github.com/crytic/fuzzstark.git && cd fuzzstark
python setup.py install
```
If you don't have cairo-lang already installed and you are on MacOS you may have an error about a missing gmp.h file even if you executed `brew install gmp`.
The following command can be used to solve it.
```bash
CFLAGS=-I`brew --prefix gmp`/include LDFLAGS=-L`brew --prefix gmp`/lib pip install ecdsa fastecdsa sympy
```
If the above command doesn't work you can find more solutions [`here`](https://github.com/OpenZeppelin/nile/issues/22).

## Usage

Run with default options.
```bash
fuzzstark tests/flags.cairo
```
When starting you will see the properties to be checked and the external functions used to generate a sequence of transactions.
```
Fuzzing the following properties:
	fuzz_flag1
External functions:
	set0
	set1
```
Eventually if a property is violated a call sequence will be presented with the order of functions to be called, the respective arguments passed, the caller address, and the events emitted represented by a starting `E`.
```
[!] fuzz_flag1 violated
Call sequence:
	set0[0] from 1
	 E set_flag0[0]
	set1[97066683862585213645535248899637309600] from 0
	 E set_flag1[97066683862585213645535248899637309600]
```

The full help menu is:
```
usage: fuzzstark [-h] [--seq-len SEQ_LEN]
                 [--blacklist-function BLACKLIST_FUNCTION [BLACKLIST_FUNCTION ...]]
                 [--psender PSENDER] [--sender SENDER [SENDER ...]]
                 [--cairo-path CAIRO_PATH [CAIRO_PATH ...]] [--coverage]
                 [--no-shrink]
                 filename

StarkNet smart contract fuzzer.

positional arguments:
  filename              Cairo file to analyze.

optional arguments:
  -h, --help            show this help message and exit
  --seq-len SEQ_LEN     Number of transactions to generate during testing.
                        (default: 10)
  --blacklist-function BLACKLIST_FUNCTION [BLACKLIST_FUNCTION ...]
                        Function name (space separated) to blacklist from
                        execution.
  --psender PSENDER     Address of the sender for property transactions.
                        (default: 1)
  --sender SENDER [SENDER ...]
                        Addresses (space separated) to use for the
                        transactions sent during testing. (default: [0, 1, 2])
  --cairo-path CAIRO_PATH [CAIRO_PATH ...]
                        A list of directories, separated by space to resolve
                        import paths.
  --coverage            Output a coverage file.
  --no-shrink           Avoid shrinking failing sequences.
```

### Writing invariants

Invariants are StarkNet view functions with names that begin with `fuzz_`, have no arguments, and return a felt. An invariant is considered failed when it returns 0.

```cairo
@view
func fuzz_flag{
        range_check_ptr,
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*
    }() -> (res: felt):
    let (flag_result) = flag.read()
    if flag_result == 1:
        return (0)
    end
    return (1)
end
```

If the flag storage variable is set to 1 the invariant will fail.

### Coverage

When the `--coverage` option is enabled, a file named covered.{time}.txt which contains the source code with coverage annotations will be saved. A line starting with `*` has been executed at least once.

Example with `tests/flags.cairo`:

```cairo
@external
*func set1{
*        syscall_ptr: felt*,
*        pedersen_ptr: HashBuiltin*,
*        range_check_ptr,
*        ecdsa_ptr: SignatureBuiltin*
*    }(val: felt):
*    let (res, remainder) = unsigned_div_rem(val, 10)
*    if remainder == 0:
*        let (flag_0) = flag0.read()
*        if flag_0 == 1:
*            flag1.write(1)
*            set_flag1.emit(val)
*            return ()
        end
*        return ()
    end
*    return()    
end
```
