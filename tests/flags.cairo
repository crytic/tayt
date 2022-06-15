%lang starknet
%builtins pedersen range_check ecdsa

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.math import unsigned_div_rem

@event
func set_flag0(value: felt):
end

@event
func set_flag1(value: felt):
end


@storage_var
func flag0() -> (res: felt):
end

@storage_var
func flag1() -> (res: felt):
end


@external
func set0{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*
    }(val: felt):
    let (res, remainder) = unsigned_div_rem(val, 100) 
    if remainder == 0:
        flag0.write(1)
        set_flag0.emit(val)
        return ()
    end
    return()    
end


@external
func set1{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*
    }(val: felt):
    let (res, remainder) = unsigned_div_rem(val, 10)
    if remainder == 0:
        let (flag_0) = flag0.read()
        if flag_0 == 1:
            flag1.write(1)
            set_flag1.emit(val)
            return ()
        end
        return ()
    end
    return()    
end


@view
func fuzz_flag1{
        range_check_ptr,
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*
    }() -> (res: felt):
    let (flag_1) = flag1.read()
    if flag_1 == 1:
        return (0)
    end
    return (1)
end
