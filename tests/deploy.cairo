%lang starknet
%builtins pedersen range_check ecdsa

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.math import unsigned_div_rem
from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.syscalls import deploy

@contract_interface
namespace Flags:
    func set0(val: felt):
    end

    func set1(val: felt):
    end

    func tayt_flag1() -> (res: felt):
    end
end

@storage_var
func flags_address() -> (res: felt):
end

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}():
    let (data: felt*) = alloc()
    let (addr) = deploy(2024779828085525422431444182955849544076259995530386260630136607064428821244, 0, 0, data)
    flags_address.write(addr)
    return ()
end

@external
func deploy_set0{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(val: felt):
    let (address) = flags_address.read()
    Flags.set0(contract_address=address, val=val)
    return ()
end

@external
func deploy_set1{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(val: felt):
    let (address) = flags_address.read()
    Flags.set1(contract_address=address, val=val)
    return ()
end

@view
func tayt_deploy_flag1{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt):
    let (address) = flags_address.read()
    let (res) = Flags.tayt_flag1(contract_address=address)
    if res == 0:
        return (0)
    end
    return (1)
end
