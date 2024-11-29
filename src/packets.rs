use std::net::IpAddr;

use anyhow::{anyhow, bail};
use pnet::packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};

pub(crate) type DPort = u16;

pub(crate) fn extract_addr_info(packet: &[u8]) -> anyhow::Result<(IpAddr, DPort)> {
    log::trace!("extract_addr_info(packet_bytes)");

    let (addr, port) = if let Some(ipv4_packet) = Ipv4Packet::new(packet) {
        get_ipv4_source_and_dest_port(ipv4_packet)?
    } else if let Some(ipv6_packet) = Ipv6Packet::new(packet) {
        get_ipv6_source_and_dest_port(ipv6_packet)?
    } else {
        bail!("packet does not belong to the IP layer");
    };

    Ok((addr, port))
}

fn get_dest_port(proto: IpNextHeaderProtocol, payload: &[u8]) -> anyhow::Result<DPort> {
    log::trace!("get_dest_port({proto}, payload_bytes)");

    match proto {
        IpNextHeaderProtocols::Tcp => match TcpPacket::new(payload) {
            Some(tcp_packet) => Ok(tcp_packet.get_destination()),
            None => Err(anyhow!("invalid TCP packet")),
        },
        IpNextHeaderProtocols::Udp => match UdpPacket::new(payload) {
            Some(udp_packet) => Ok(udp_packet.get_destination()),
            None => Err(anyhow!("invalid UDP packet")),
        },
        other => Err(anyhow!("unsupported protocol: {other}")),
    }
}
fn get_ipv4_source_and_dest_port(packet: Ipv4Packet) -> anyhow::Result<(IpAddr, DPort)> {
    log::trace!("get_ipv4_source_and_dest_port(packet)");

    let port = match get_dest_port(packet.get_next_level_protocol(), packet.payload()) {
        Ok(port) => port,
        Err(err) => {
            bail!("unable to get IPv4 destination port ({err})");
        }
    };

    Ok((packet.get_source().into(), port))
}

fn get_ipv6_source_and_dest_port(packet: Ipv6Packet) -> anyhow::Result<(IpAddr, DPort)> {
    log::trace!("get_ipv6_source_and_dest_port(packet)");

    let port = match get_dest_port(packet.get_next_header(), packet.payload()) {
        Ok(port) => port,
        Err(err) => {
            bail!("unable to get IPv6 destination port ({err})");
        }
    };

    Ok((packet.get_source().into(), port))
}
