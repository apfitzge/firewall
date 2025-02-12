#![no_std]
#![no_main]

use {
    aya_ebpf::{
        bindings::xdp_action,
        macros::{map, xdp},
        maps::HashMap,
        programs::XdpContext,
    },
    aya_log_ebpf::info,
    network_types::{
        eth::{EthHdr, EtherType},
        ip::Ipv4Hdr,
    },
};

macro_rules! read_field {
    ($struct_ptr: ident: $struct_type: ty, $field_name: ident: $field_type: ty) => {
        *($struct_ptr.byte_add(core::mem::offset_of!($struct_type, $field_name))
            as *const $field_type)
    };
}

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(2048, 0);

#[inline(always)]
fn is_ip_blocked(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address) }.is_some()
}

#[xdp]
pub fn firewall(ctx: XdpContext) -> u32 {
    match try_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn checked_get_pointer<T: Sized>(offset: &mut *const u8, end: *const u8) -> Result<*const T, ()> {
    let new_offset = unsafe { offset.byte_add(core::mem::size_of::<T>()) };
    if new_offset > end {
        return Err(());
    }
    let result = *offset as *const T;
    *offset = new_offset;
    Ok(result)
}

fn try_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let mut offset = ctx.data() as *const u8;
    let end = ctx.data_end() as *const u8;

    let ethhdr: *const EthHdr = checked_get_pointer(&mut offset, end)?;
    match unsafe { read_field!(ethhdr: EthHdr, ether_type: EtherType) } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = checked_get_pointer(&mut offset, end)?;
    let source_addr = u32::from_be(unsafe { read_field!(ipv4hdr: Ipv4Hdr, src_addr: u32) });

    let action = if is_ip_blocked(source_addr) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    info!(
        &ctx,
        "received a packet from {:i}. Action: {}", source_addr, action
    );

    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
