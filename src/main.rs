extern crate pnet;

use std::env;
use std::net;
use std::error;
use std::str::FromStr;

use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::MutablePacket;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer3};
use pnet::util;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

static IPV4_HDR_LEN: usize = 21;
static ICMP_HDR_LEN: usize = 8;
static ICMP_PYLD_LEN: usize = 32;

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.len() {
        2 => {
            let hop_list = build_hop_list(&args[1]).unwrap();
            println!("hop_list returned: {:?}", hop_list);
        }

        _ => println!("Usage: {} ip", args[0]),
   }

}

fn build_hop_list(ip_addr: &String) -> Result<Vec<(net::IpAddr, u8)>> {
    let protocol = Layer3(IpNextHeaderProtocols::Icmp);
    
    let (mut tx, mut rx) = transport_channel(1024, protocol)
        .map_err(|err| format!("Error opening the channel: {}", err)).unwrap();

    let ip_addr = net::Ipv4Addr::from_str(&ip_addr).map_err(|_| "invalid address").unwrap();
    
    let mut rx = icmp_packet_iter(&mut rx);
    let mut ttl = 1;
    let mut prev_addr = None;

    let mut hop_list = Vec::new();

    loop {
        let mut ip_buf = [0u8; 60];
        let mut icmp_buf = [0u8; 40];
                
        let icmp_packet = create_icmp_packet(&mut ip_buf, &mut icmp_buf, ip_addr, ttl).unwrap();

        tx.send_to(icmp_packet, net::IpAddr::V4(ip_addr)).unwrap();
        if let Ok((_, addr)) = rx.next() {
            if Some(addr) == prev_addr {
                println!("prev: {}", addr.to_string());
                return Ok(hop_list);
            }
            prev_addr = Some(addr);
                    
            hop_list.push((addr, ttl));
            println!("TTL: {} - {:?}", ttl, addr.to_string());
        }
        ttl += 1;
        println!("hop_list {:?}", hop_list);
    }

}

fn create_icmp_packet<'a>(
    ip_buf: &'a mut [u8],
    icmp_buf: &'a mut [u8],
    dest: net::Ipv4Addr, 
    ttl: u8) -> Result<MutableIpv4Packet<'a>> {

    let mut ipv4_packet = MutableIpv4Packet::new(ip_buf).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HDR_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HDR_LEN + ICMP_HDR_LEN + ICMP_PYLD_LEN) as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);

    let mut icmp_packet = MutableEchoRequestPacket::new(icmp_buf).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = util::checksum(&icmp_packet.packet_mut(), 2);
    icmp_packet.set_checksum(checksum);

    println!("Making it here");
    ipv4_packet.set_payload(icmp_packet.packet_mut());
    Ok(ipv4_packet)
}
