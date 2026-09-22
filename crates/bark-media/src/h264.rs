//! Just enough H.264 bitstream reading to know what a frame contains.
//!
//! Encoders output Annex B: NAL units separated by 00 00 01 or 00 00 00 01
//! start codes. BARK needs two facts from that: whether a frame is a keyframe
//! (an IDR picture, NAL type 5), and whether it carries the sequence and
//! picture parameter sets (types 7 and 8) a decoder needs before it can
//! decode anything.

pub const NAL_IDR: u8 = 5;
pub const NAL_SPS: u8 = 7;
pub const NAL_PPS: u8 = 8;

/// The type of every NAL unit in an Annex B buffer, in order.
pub fn nal_types(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            if let Some(&h) = data.get(i + 3) {
                out.push(h & 0x1F);
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

pub fn is_keyframe(data: &[u8]) -> bool {
    nal_types(data).contains(&NAL_IDR)
}

pub fn has_parameter_sets(data: &[u8]) -> bool {
    let t = nal_types(data);
    t.contains(&NAL_SPS) && t.contains(&NAL_PPS)
}

/// Converts an `avcC`-style sequence header (length-prefixed or already
/// Annex B, depending on the encoder) into Annex B, for prepending to a
/// keyframe that arrived without its parameter sets.
pub fn to_annex_b(header: &[u8]) -> Vec<u8> {
    if header.starts_with(&[0, 0, 0, 1]) || header.starts_with(&[0, 0, 1]) {
        return header.to_vec();
    }
    // MF_MT_MPEG_SEQUENCE_HEADER for H.264 is Annex B on every encoder seen
    // so far; anything else is passed through untouched rather than guessed.
    header.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nal_types_after_both_start_code_lengths() {
        let data = [0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 3, 0, 0, 0, 1, 0x65, 9, 9];
        assert_eq!(nal_types(&data), vec![7, 8, 5]);
        assert!(is_keyframe(&data));
        assert!(has_parameter_sets(&data));
    }

    #[test]
    fn a_p_frame_is_not_a_keyframe() {
        let data = [0, 0, 0, 1, 0x41, 1, 2, 3];
        assert_eq!(nal_types(&data), vec![1]);
        assert!(!is_keyframe(&data));
        assert!(!has_parameter_sets(&data));
    }

    #[test]
    fn empty_and_garbage_input_are_harmless() {
        assert!(nal_types(&[]).is_empty());
        assert!(nal_types(&[0, 0]).is_empty());
        assert!(nal_types(&[0, 0, 1]).is_empty());
    }
}
