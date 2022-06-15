from typing import List, Set
from dataclasses import make_dataclass
import asyncio
from starkware.cairo.lang.vm.cairo_pie import ExecutionResources
from starkware.starknet.core.os import syscall_utils
from starkware.starknet.business_logic.execution.objects import CallInfo
from starkware.cairo.lang.vm.trace_entry import TraceEntry
from starkware.cairo.lang.vm.relocatable import MaybeRelocatable
from starkware.starknet.business_logic.execution.execute_entry_point import ExecuteEntryPoint
from starkware.starknet.business_logic.utils import get_return_values

CallInfoPc = make_dataclass("CallInfoPc", fields=[("pc", Set[int])], bases=(CallInfo,), frozen=True)

# We make _build_call_info returns a CallInfoPc that has a list of PCs executed
def _hooked_build_call_info(
    self,
    previous_cairo_usage: ExecutionResources,
    syscall_handler: syscall_utils.BusinessLogicSysCallHandler,
    retdata: List[int],
    trace: List[TraceEntry[MaybeRelocatable]],
) -> CallInfo:

    call_info_pc = CallInfoPc(
        caller_address=self.caller_address,
        call_type=self.call_type,
        contract_address=self.contract_address,
        code_address=self.code_address,
        class_hash=self._get_class_hash(state=syscall_handler.state),
        entry_point_selector=self.entry_point_selector,
        entry_point_type=self.entry_point_type,
        calldata=self.calldata,
        retdata=retdata,
        execution_resources=syscall_handler.state.cairo_usage - previous_cairo_usage,
        events=syscall_handler.events,
        l2_to_l1_messages=syscall_handler.l2_to_l1_messages,
        storage_read_values=syscall_handler.starknet_storage.read_values,
        accessed_storage_keys=syscall_handler.starknet_storage.accessed_addresses,
        internal_calls=syscall_handler.internal_calls,
        # entry.pc is a RelocatableValue, however we know that pc is in the execution segment (0)
        # so we can keep only the offset
        pc={entry.pc.offset for entry in trace},
    )

    return call_info_pc

# Call _build_call_info with the trace argument
def _hooked_sync_execute(
    self,
    state: "CarriedState",
    general_config: "StarknetGeneralConfig",
    loop: asyncio.AbstractEventLoop,
    tx_execution_context: "TransactionExecutionContext",
) -> CallInfo:

    previous_cairo_usage = state.cairo_usage

    runner, syscall_handler = self._run(
        state=state,
        general_config=general_config,
        loop=loop,
        tx_execution_context=tx_execution_context,
    )

    # Apply modifications to the contract storage.
    state.update_contract_storage(
        contract_address=self.contract_address,
        modifications=syscall_handler.starknet_storage.get_modifications(),
    )

    # Update resources usage (for bouncer).
    state.cairo_usage += runner.get_execution_resources()
    if "ec_op_builtin" in state.cairo_usage.builtin_instance_counter:
        del state.cairo_usage.builtin_instance_counter["ec_op_builtin"]

    # Build and return call info.
    return self._build_call_info(
        previous_cairo_usage=previous_cairo_usage,
        syscall_handler=syscall_handler,
        retdata=get_return_values(runner=runner),
        # Trace with the PCs executed
        trace=runner.vm.trace,
    )


def hook():
    ExecuteEntryPoint._build_call_info = _hooked_build_call_info
    ExecuteEntryPoint.sync_execute = _hooked_sync_execute
