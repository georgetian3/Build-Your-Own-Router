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

#include <fstream>


void mac_cpy(uint8_t* dst, const uint8_t* src) {
    memcpy(dst, src, ETHER_ADDR_LEN);
}

bool mac_eq(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, ETHER_ADDR_LEN);
}


namespace simple_router {


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
    }

    std::cerr << getRoutingTable() << std::endl;



    // FILL THIS IN

    print_hdr_eth(packet.data());
    ethernet_hdr* ether_hdr = (ethernet_hdr *)packet.data();

    /* Your router must ignore Ethernet frames not destined to the router, i.e., when destination hard-
    ware address is neither the corresponding MAC address of the interface nor a broadcast address
    ( FF:FF:FF:FF:FF:FF ). */
    const uint8_t broadcast_address[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (!mac_eq(ether_hdr->ether_dhost, broadcast_address) ||
        !mac_eq(ether_hdr->ether_dhost, iface->addr.data())) {
        return;
    }

    /* Your router must appropriately dispatch Ethernet frames (their payload) carrying ARP and IPv4
    packets. */


    uint8_t* ether_payload = reinterpret_cast<uint8_t*>(packet.data() + (uint8_t*)sizeof(ethernet_hdr));

    // Your router should ignore Ethernet frames other than ARP and IPv4.
    int ether_type = ntohs(ether_hdr->ether_type);
    if (ether_type == ethertype_arp) {

        arp_hdr* arp = reinterpret_cast<arp_hdr*>(ether_payload);
        print_hdr_arp(ether_payload);

        if (arp->arp_op == arp_op_request) {

            /* Must ignore other ARP requests */
            // drop ARP requests whose target HW addr does not match this interface
            if (!mac_eq(arp->arp_tha, iface->addr.data())) {
                return;
            }
            
            /* Must properly respond to ARP requests for MAC address for the IP address of the correspond-
            ing network interface */

            mac_cpy(ether_hdr->ether_shost, iface->addr.data());
            mac_cpy(ether_hdr->ether_dhost, arp->arp_sha);

            arp->arp_op = arp_op_reply;
            arp->arp_tip = arp->arp_sip;
            mac_cpy(arp->arp_tha, arp->arp_sha);
            arp->arp_sip = iface->ip;
            copy_mac_addr(arp_hdr->arp_sha, iface->addr);


            memcpy(ether_payload, arp, sizeof(arp_hdr));
            sendPacket(packet, iface);
            return;
        }
        
        else if (arp->arp_op == arp_op_reply) {
            /* When router receives an ARP reply, it should record IP-MAC mapping information in ARP cache
            (Source IP/Source hardware address in the ARP reply). Afterwards, the router should send out all
            corresponding enqueued packets. */
            // TODO: handle request
            std::shared_ptr<ArpRequest> request = insertArpEntry(arp->arp_sha, arp->arp_sip);

        }
    } else if (ether_type == ethertype_ip) {
        ip_hdr* ip_h = reinterpret_cast<ip_hdr*>(ether_payload);

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
    os << iface << "\n";
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
