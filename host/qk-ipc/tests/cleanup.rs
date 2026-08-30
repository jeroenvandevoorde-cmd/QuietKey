//! Source locks for the private cleanup boundary and all frame exit paths.

const STREAM: &str = include_str!("../src/stream.rs");
const WIPE: &str = include_str!("../src/wipe.rs");

#[test]
fn allocation_drop_clears_complete_capacity_with_a_fence() {
    assert!(WIPE.contains("let capacity = self.0.capacity();"));
    assert!(WIPE.contains("allocation(self.0.as_mut_ptr(), capacity);"));
    assert!(WIPE.contains("ptr::write_volatile(pointer.add(offset), 0)"));
    assert!(WIPE.contains("compiler_fence(Ordering::SeqCst);"));
}

#[test]
fn received_and_decoder_drop_paths_retain_cleanup_ownership() {
    let received_drop = STREAM
        .split_once("impl Drop for ReceivedFrame")
        .expect("received drop")
        .1
        .split_once("/// Pure, bounded decoder")
        .expect("received drop end")
        .0;
    assert!(received_drop.contains("wipe::bytes(&mut self.header.session_id);"));

    let decoder_drop = STREAM
        .split_once("impl Drop for StreamDecoder")
        .expect("decoder drop")
        .1
        .split_once("#[cfg(test)]")
        .expect("decoder drop end")
        .0;
    assert!(decoder_drop.contains("wipe::bytes(&mut self.header_bytes);"));
    assert!(decoder_drop.contains("wipe::bytes(&mut header.session_id);"));
}

#[test]
fn every_decoder_rejection_routes_through_the_terminating_clear() {
    assert!(STREAM.contains("return Err(self.terminate(IpcError::AncillaryData));"));
    assert!(STREAM.contains("Err(error) => return Err(self.terminate(error))"));
    assert!(STREAM.contains("return Err(self.terminate(IpcError::PayloadAllocationFailed))"));
    assert!(STREAM.contains("return Err(self.terminate(IpcError::InvalidTransition))"));
    let terminate = STREAM
        .split_once("fn terminate(&mut self, error: IpcError)")
        .expect("terminate helper")
        .1
        .split_once("impl Default for StreamDecoder")
        .expect("terminate helper end")
        .0;
    assert!(terminate.contains("wipe::bytes(&mut self.header_bytes);"));
    assert!(terminate.contains("wipe::bytes(&mut header.session_id);"));
    assert!(terminate.contains("self.payload = WipingByteVec::default();"));
    assert!(terminate.contains("self.terminated = true;"));
}

#[test]
fn caught_unwind_and_exact_byte_accounting_are_executable_unit_tests() {
    assert!(WIPE.contains("allocation_owner_clears_during_caught_unwind"));
    assert!(STREAM.contains("successful_owner_drop_clears_header_session_and_payload_capacity"));
    assert!(STREAM.contains("partial_decoder_drop_clears_header_session_and_payload_capacity"));
    assert!(STREAM.contains("ancillary_termination_clears_partial_state_before_latching"));
    assert!(STREAM.contains("received_owner_clears_during_caught_unwind"));
}
