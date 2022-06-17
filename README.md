# TBD

TBD is a StarkNet smart contract fuzzer.

## Usage
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
