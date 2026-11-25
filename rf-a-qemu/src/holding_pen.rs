// Copyright The Rusted Firmware-A Contributors.
//
// SPDX-License-Identifier: BSD-3-Clause

use super::{QemuCoreIndex, TRUSTED_MAILBOX_BASE};
use core::{arch::asm, mem::offset_of};
use rf_a_core::{
    aarch64::{dsb_sy, sev},
    context::CoreIndex,
    naked_asm,
    platform::my_core_pos,
};


const HOLD_BOOT_MAGIC1: u64 = 0xCAFE_CAFE;
const HOLD_BOOT_MAGIC2: u64 = 0xBEEF_BEEF;
const HOLD_SUSPEND_MAGIC1: u64 = 0xBA5E_BA11;
const HOLD_SUSPEND_MAGIC2: u64 = 0xFEED_F00D;
const HOLD_STATE_WAIT: u64 = !0;

const HOLD_SLOTS: *mut [HoldSlot; QemuCoreIndex::CORE_COUNT] = TRUSTED_MAILBOX_BASE as _;

#[repr(C, align(64))]
struct HoldSlot {
    entry: u64,
    magic1: u64,
    magic2: u64,
}

/// Initialise the hold pen by writing magic tags to every slot.
pub fn hold_pen_init() {
    // SAFETY: `TRUSTED_MAILBOX_BASE` is the base address of the shared mailbox device memory.
    // Other cores are concurrently reading from this region, but aligned 64bit writes are
    // 'single-copy atomic' as they will either complete in full or not at all.
    unsafe {
        for i in 0..QemuCoreIndex::CORE_COUNT {
            let slot_ptr = &raw mut (*HOLD_SLOTS)[i];

            (&raw mut (*slot_ptr).entry).write_volatile(HOLD_STATE_WAIT);

            // Ensure the entry value is committed before the magic
            // tags that make this slot visible to polling secondaries.
            asm!("dmb sy");

            (&raw mut (*slot_ptr).magic1).write_volatile(HOLD_BOOT_MAGIC1);
            (&raw mut (*slot_ptr).magic2).write_volatile(HOLD_BOOT_MAGIC2);

            hold_pen_signal(i, secondary_cold_boot_setup);
        }
    }
}

/// Signal a secondary core to branch to the given entrypoint.
pub fn hold_pen_signal(cpu_index: usize, entrypoint: unsafe extern "C" fn() -> !) {
    // SAFETY: `TRUSTED_MAILBOX_BASE` is the base address of the shared mailbox device memory.
    // Other cores are concurrently reading from or writing to this region, but aligned 64bit writes
    // are 'single-copy atomic' as they will either complete in full or not at all.
    unsafe {
        let slot_ptr = &raw mut (*HOLD_SLOTS)[cpu_index];
        (&raw mut (*slot_ptr).entry).write_volatile(entrypoint as usize as u64);
    }

    // Ensure that the entry value is committed before signalling secondary cores to wake up.
    dsb_sy();

    // Signal the secondary core to wake up and jump to the given entrypoint.
    sev();
}

/// Signal a secondary core to branch to the given entrypoint.
pub fn hold_pen_signal_suspend(cpu_index: usize, entrypoint: unsafe extern "C" fn() -> !) {
    // SAFETY: `TRUSTED_MAILBOX_BASE` is the base address of the shared mailbox device memory.
    // Other cores are concurrently reading from or writing to this region, but aligned 64bit writes
    // are 'single-copy atomic' as they will either complete in full or not at all.
    unsafe {
        let slot_ptr = &raw mut (*HOLD_SLOTS)[cpu_index];

        (&raw mut (*slot_ptr).magic1).write_volatile(HOLD_SUSPEND_MAGIC1);
        (&raw mut (*slot_ptr).magic2).write_volatile(HOLD_SUSPEND_MAGIC2);
        hold_pen_signal(cpu_index, entrypoint);

        // Ensure the entry value is committed before the magic
        // tags that make this slot visible to polling secondaries.
        asm!("dmb sy");
    }
}

/// Polls the holding pen for the given core until the magic tags and entrypoint are set, then
/// jumps to the entrypoint. This is called by secondary cores after waking up from a power-down
/// state.
#[unsafe(naked)]
pub unsafe extern "C" fn secondary_cold_boot_setup() -> ! {
    naked_asm!(
        "bl  {plat_my_core_pos}",
        // x0 = core index
        "mov x1, #{HOLD_SLOT_SIZE}",
        "ldr x2, ={HOLD_SLOTS_BASE}",
        "madd x2, x0, x1, x2", // x2 = HOLD_SLOTS_BASE + core_pos * HOLD_SLOT_SIZE

        "ldr x0, [x2, #{MAGIC1_OFFSET}]", // load magic1
        "ldr x1, ={HOLD_SUSPEND_MAGIC1}",
        "cmp x0, x1",
        "b.ne 0f",

        "ldr x0, [x2, #{MAGIC2_OFFSET}]", // load magic2
        "ldr x1, ={HOLD_SUSPEND_MAGIC2}",
        "cmp x0, x1",
        "b.eq 3f",

    "0:",
        "bl  {plat_my_core_pos}",
        // x0 = core index
        "mov x1, #{HOLD_SLOT_SIZE}",
        "ldr x2, ={HOLD_SLOTS_BASE}",
        "madd x2, x0, x1, x2", // x2 = HOLD_SLOTS_BASE + core_pos * HOLD_SLOT_SIZE

    "1:",
        // Ensure that the loads above are totally completed before we load the entrypoint.
        // This prevents the pipeline from speculatively pulling a stale 'entry' value.
        "dmb sy",

        "ldr x0, [x2, #{MAGIC1_OFFSET}]", // load magic1
        "ldr x1, ={HOLD_BOOT_MAGIC1}",
        "cmp x0, x1",
        "b.ne 2f",

        "ldr x0, [x2, #{MAGIC2_OFFSET}]", // load magic2
        "ldr x1, ={HOLD_BOOT_MAGIC2}",
        "cmp x0, x1",
        "b.ne 2f",

        "ldr x16, [x2, #{ENTRY_OFFSET}]", // load entry
        "ldr x1, ={HOLD_STATE_WAIT}",
        "cmp x16, x1",
        "b.eq 2f",

        // Prevent reuse of stale entry
        "str x1, [x2, #{ENTRY_OFFSET}]", // reset to wait
        // x16 is chosen to make this bti c compatible, not just bti j
        "br x16",
    "2:",
        "wfe",
        "b 1b",
    "3:",
        "wfi",
        // Waking up from wfi, re-init the core's holding pen slot.
        "bl  {plat_my_core_pos}",
        // x0 = core index
        "mov x1, #{HOLD_SLOT_SIZE}",
        "ldr x2, ={HOLD_SLOTS_BASE}",
        "madd x2, x0, x1, x2", // x2 = HOLD_SLOTS_BASE + core_pos * HOLD_SLOT_SIZE
        "ldr x1, ={HOLD_BOOT_MAGIC1}",
        "str x1, [x2, #{MAGIC1_OFFSET}]", // store magic1
        "ldr x1, ={HOLD_BOOT_MAGIC2}",
        "str x1, [x2, #{MAGIC2_OFFSET}]", // store magic2
        "b 0b",
        HOLD_SLOT_SIZE = const core::mem::size_of::<HoldSlot>(),
        ENTRY_OFFSET = const offset_of!(HoldSlot, entry),
        MAGIC1_OFFSET = const offset_of!(HoldSlot, magic1),
        MAGIC2_OFFSET = const offset_of!(HoldSlot, magic2),
        HOLD_SLOTS_BASE = const TRUSTED_MAILBOX_BASE,
        HOLD_BOOT_MAGIC1 = const HOLD_BOOT_MAGIC1,
        HOLD_BOOT_MAGIC2 = const HOLD_BOOT_MAGIC2,
        HOLD_STATE_WAIT = const HOLD_STATE_WAIT,
        HOLD_SUSPEND_MAGIC1 = const HOLD_SUSPEND_MAGIC1,
        HOLD_SUSPEND_MAGIC2 = const HOLD_SUSPEND_MAGIC2,
        plat_my_core_pos = sym my_core_pos::<QemuCoreIndex>,
    );
}
