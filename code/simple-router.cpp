/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"
#include "pdu.hpp"
#include <fstream>


namespace simple_router {


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

const Buffer broadcast_address = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void SimpleRouter::send_or_queue(const Buffer& packet, const Interface* iface) {
    std::cerr << "Send or queue" << std::endl;
    IP ip(packet);
    auto arp_entry = m_arp.lookup(ip.get_ip_dst_ip());
    if (arp_entry == nullptr) {
        std::cerr << "Destination MAC uncached, queuing request" << std::endl;
        m_arp.queueRequest(ip.get_ip_dst_ip(), packet, iface->name);
    } else {
        std::cerr << "Destination MAC known, sending to " << macToString(arp_entry->mac) << std::endl;
        ip.set_eth_dst(arp_entry->mac.data());
        sendPacket(ip.data(), iface->name);
    }
}

void SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface) {

    //printIfaces(std::cerr);
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << " at " << steady_clock::now().time_since_epoch().count() / 1000000000.0 << std::endl;
    print_hdrs(packet);

    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
    }

    // FILL THIS IN

    Ethernet eth(packet);
    if (!eth.verify_length()) {
        std::cerr << "Ethernet header too short, ignore" << std::endl;
        return;
    }

    if (eth.get_eth_dst() != broadcast_address &&
        eth.get_eth_dst() != iface->addr) {
        std::cerr << "Ethernet dest MAC addr != iface/broadcast, ignore" << std::endl;
        return;
    }

    if (eth.get_eth_type() == ethertype_arp) {
        std::cerr << "Received ARP packet" << std::endl;

        ARP arp(packet);

        if (!arp.verify_length()) {
            std::cerr << "ARP packet too short, ignore" << std::endl;
            return;
        }

        if (arp.get_arp_opcode() == arp_op_request) {
            std::cerr << "Received ARP request" << std::endl;
            if (arp.get_arp_dst_ip() != iface->ip) {
                std::cerr << "ARP dest IP != iface IP, ignore" << std::endl;
                return;
            }
            ARP reply(packet);
            reply.make_arp_reply(iface->addr.data());
            std::cerr << "Sending ARP reply" << std::endl;
            sendPacket(reply.data(), iface->name);
            return;
        } else if (arp.get_arp_opcode() == arp_op_reply) {
            std::cerr << "Received ARP reply" << std::endl;
            auto arp_requests = m_arp.insertArpEntry(arp.get_arp_src_mac(), arp.get_arp_src_ip());
            if (arp_requests == nullptr) {
                std::cerr << "Cannot queue packet, ignore" << std::endl;
                return;
            } else {
                for (const auto& pending: arp_requests->packets) {
                    std::cerr << "Sending queued packets" << std::endl;
                    IP forwarded(pending.packet);
                    forwarded.set_eth_src(findIfaceByName(pending.iface)->addr.data());
                    forwarded.set_eth_dst(arp.get_arp_src_mac().data());
                    sendPacket(forwarded.data(), pending.iface);
                }
                m_arp.removeRequest(arp_requests);
            }
        } else {
            std::cerr << "ARP opcode is neither request or reply, ignoring" << std::endl;
            return;
        }
    } else if (eth.get_eth_type() == ethertype_ip) {
        std::cerr << "Received IP packet" << std::endl;

        IP ip(packet);
        if (!ip.verify_length()) {
            std::cerr << "IP header too short, ignore" << std::endl;
            return;
        }
        if (!ip.verify_checksum()) {
            std::cerr << "IP checksum incorrect, ignore" << std::endl;
            return;
        }



        bool ip_to_router = false;
        for (const auto& iface: m_ifaces) {
            if (iface.ip == ip.get_ip_dst_ip()) {
                ip_to_router = true;
                break;
            }
        }

        if (ip_to_router) {

            std::cerr << "IP to router" << std::endl;

            if (ip.get_ip_protocol() == 6 || // TCP
                ip.get_ip_protocol() == 17) { // UDP

                std::cerr << "Received TCP or UDP" << std::endl;
                ICMP icmp(packet);
                icmp.make_port_unreachable(iface->ip);
                std::cerr << "Sending port unreachable" << std::endl;
                send_or_queue(icmp.data(), iface);
                return;
            }
            if (ip.get_ip_protocol() != ip_protocol_icmp) {
                std::cerr << "Received unknown IP protocol: " << (int)ip.get_ip_protocol() << ", ignore" << std::endl;
                return;
            }
            
            ICMP icmp(packet);
            if (!icmp.verify_length()) {
                std::cerr << "ICMP header too short, ignore" << std::endl;
                return;
            }
            if (!icmp.verify_checksum()) {
                std::cerr << "ICMP checksum incorrect, ignore" << std::endl;
                return;
            }

            if (icmp.get_icmp_type() != 8) { // if not echo request
                std::cerr << "ICMP type unknown" << std::endl;
                return;
            }

            std::cerr << "Received ICMP echo request" << std::endl;

            icmp.make_echo_reply(iface->addr.data());

            send_or_queue(icmp.data(), iface);

            return;

        }

        ip.decrement_ttl();
        if (ip.get_ip_ttl() == 0) {
            std::cerr << "TTL = 0, sending time exceeded ICMP" << std::endl;
            ICMP icmp(packet);
            icmp.make_time_exceeded(iface->ip, iface->addr.data(), 0);
            send_or_queue(icmp.data(), iface);
            return; 
        }


        std::cerr << "IP to forward" << std::endl;

        ip.make_forwarded(iface->addr.data());

        


        std::cerr << "Forwarding IP packet" << std::endl;
        RoutingTableEntry next_hop;
        try {
            next_hop = m_routingTable.lookup(ip.get_ip_dst_ip());
        } catch (...) {
            std::cerr << "Next hop lookup failed" << std::endl;
            return;
        }
        send_or_queue(ip.data(), findIfaceByName(next_hop.ifName));


    } else {
        // Your router should ignore Ethernet frames other than ARP and IPv4.
        std::cerr << "Unrecognized ethernet type" << std::endl;
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
    
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "" << std::endl;
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
