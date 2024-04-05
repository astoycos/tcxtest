#![no_std]
#![no_main]

use aya_ebpf::{macros::classifier, programs::TcContext, bindings::{TCX_NEXT, TCX_PASS}};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use core::mem;


// Gives us raw pointers to a specific offset in the packet
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, i64> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(TCX_PASS.into());
    }
    Ok((start + offset) as *mut T)
}


#[classifier]
pub fn tcxtestlast(ctx: TcContext) -> i32 {
    match try_tcxtestlast(ctx) {
        Ok(ret) => ret,
        Err(_ret) => TCX_PASS,
    }
}

fn try_tcxtestlast(ctx: TcContext) -> Result<i32, i64> {
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0) }?;
    match unsafe { *eth_hdr }.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            match unsafe { *ipv4hdr }.proto {
                IpProto::Icmp => {
                    info!(&ctx, "received a packet last");
                    return Ok(TCX_NEXT)
                },
                _ => {
                    return Ok(TCX_PASS)
                }
                    ,
            }
        }
        _ => return Ok(TCX_PASS),
    }
}

#[classifier]
pub fn tcxtestfirst(ctx: TcContext) -> i32 {
    match try_tcxtestfirst(ctx) {
        Ok(ret) => ret,
        Err(_ret) => TCX_PASS,
    }
}

fn try_tcxtestfirst(ctx: TcContext) -> Result<i32, i64> {
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0) }?;
    match unsafe { *eth_hdr }.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            match unsafe { *ipv4hdr }.proto {
                IpProto::Icmp => {
                    info!(&ctx, "received a packet first");
                    return Ok(TCX_NEXT)
                },
                _ => {
                    return Ok(TCX_PASS)
                }
                    ,
            }
        }
        _ => return Ok(TCX_PASS),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
