#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = btlightning::parse_frame_header(data, btlightning::DEFAULT_MAX_FRAME_PAYLOAD);
});
