// Copyright The Rusted Firmware-A Contributors.
//
// SPDX-License-Identifier: BSD-3-Clause

//! Read the AArch64 TF-A executable-image list while BL2's SRAM is still mapped.

use super::BL31_BASE;
use rf_a_core::context::EntryPointInfo;

// TF-A plat/qemu/qemu/include/platform_def.h: BL2_BASE .. BL2_LIMIT.
pub(super) const BL2_BASE: usize = BL31_BASE - 0x0003_5000;

// TF-A include/export/common/{bl_common,ep_info,param_header}_exp.h.
const PARAM_BL_PARAMS: u8 = 5;
const PARAM_EP: u8 = 1;
const BL33_IMAGE_ID: u32 = 5;
const EP_SECURITY_MASK: u32 = 0x21;
const EP_NON_SECURE: u32 = 1;
const EP_EXECUTABLE: u32 = 1 << 3;

#[repr(C)]
struct Header {
    kind: u8,
    version: u8,
    size: u16,
    attr: u32,
}

#[repr(C)]
struct Params {
    header: Header,
    head: usize,
}

#[repr(C)]
struct Node {
    image_id: u32,
    _image_info: usize,
    entry: usize,
    next: usize,
}

#[repr(C)]
struct Entry {
    header: Header,
    pc: usize,
    _spsr: u32,
    args: [u64; 8],
}

fn checked_ptr<T>(address: usize) -> *const T {
    let ptr = address as *const T;
    assert!(
        ptr.is_aligned() && (BL2_BASE..=BL31_BASE - size_of::<T>()).contains(&address),
        "BL2 descriptor outside its SRAM or misaligned: {address:#x}"
    );
    ptr
}

pub(super) fn bl33_entry(address: usize) -> EntryPointInfo {
    // SAFETY: BL2 supplied initialized, immutable AArch64 descriptors; checked_ptr bounds and
    // aligns each read within the read-only early BL2 mapping. All fields are integer types.
    let params = unsafe { checked_ptr::<Params>(address).read() };
    assert!(
        params.header.kind == PARAM_BL_PARAMS
            && params.header.version >= 2
            && usize::from(params.header.size) >= size_of::<Params>(),
        "expected TF-A v2 BL parameters"
    );
    let mut next = params.head;
    for _ in 0..(BL31_BASE - BL2_BASE) / size_of::<Node>() {
        if next == 0 {
            break;
        }
        // SAFETY: Same descriptor and early-mapping guarantees as above.
        let node = unsafe { checked_ptr::<Node>(next).read() };
        if node.image_id == BL33_IMAGE_ID {
            // SAFETY: Same descriptor and early-mapping guarantees as above.
            let ep = unsafe { checked_ptr::<Entry>(node.entry).read() };
            assert!(
                ep.header.kind == PARAM_EP
                    && usize::from(ep.header.size) >= size_of::<Entry>()
                    && ep.header.attr & EP_SECURITY_MASK == EP_NON_SECURE
                    && ep.header.attr & EP_EXECUTABLE != 0
                    && ep.pc != 0
                    && ep.pc.is_multiple_of(4),
                "invalid BL33 non-secure executable entry"
            );
            return EntryPointInfo {
                pc: ep.pc,
                args: ep.args,
            };
        }
        next = node.next;
    }
    panic!("BL33 entry missing from TF-A boot parameters");
}
