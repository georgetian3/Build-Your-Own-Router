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
        
        printf("Ignoring ethernet frame\n");
        return;
    }

    /* Your router must appropriately dispatch Ethernet frames (their payload) carrying ARP and IPv4
    packets. */

    Buffer ether_data(packet.begin() + sizeof(ether_hdr), packet.end());

    // Your router should ignore Ethernet frames other than ARP and IPv4.
    int ether_type = ntohs(ether_hdr->ether_type);
    if (ether_type == ethertype_arp) {

        arp_hdr* arp = (arp_hdr*)ether_data.data();
        print_hdr_arp((uint8_t*)arp);

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
            mac_cpy(arp->arp_sha, iface->addr.data());


            sendPacket(packet, inIface);
            return;
        }
        
        else if (arp->arp_op == arp_op_reply) {
            /* When router receives an ARP reply, it should record IP-MAC mapping information in ARP cache
            (Source IP/Source hardware address in the ARP reply). Afterwards, the router should send out all
            corresponding enqueued packets. */
            // TODO: handle request
            //std::shared_ptr<ArpRequest> request = insertArpEntry(arp->arp_sha, arp->arp_sip);

        }
    } else if (ether_type == ethertype_ip) {

        ////////////////////////////////////////// BEGIN 2.3 IPv4 PACKETS ////////////////////////////////////////////////

        /* For each incoming IPv4 packet, your router should verify its checksum and the minimum length of
        an IP packet
        – Invalid packets must be discarded (a proper ICMP error response is NOT required for this
        project). */
        #pragma region // verify minimum length
            #ifndef IP_MINPACKET
                #define IP_MINPACKET sizeof(ip_hdr) // min packet length is simply length of header with no options
            #endif
            int packet_length = packet.size() - sizeof(ether_hdr);
            if (packet_length < IP_MINPACKET) {
                printf("IP too short\n");
                return;
            }
        #pragma endregion 
        #pragma region // verify checksum
        ip_hdr* ip_h = (ip_hdr*)ether_data.data();
        print_hdr_ip((uint8_t*)ip_h);

        uint16_t checksum = cksum(ip_h, sizeof(ip_hdr));
        if (checksum != 0) {
            printf("IP checksum incorrect\n");
            return;
        }
        #pragma endregion

        std::vector<uint8_t> ip_data(ether_data.begin() + sizeof(ip_hdr), ether_data.end());

        /* Your router should classify datagrams into (1) destined to the router (to one of the IP addresses of
        the router), and (2) datagrams to be forwarded: */
        if (ip_h->ip_dst == iface->ip) {
            /* For (1), if packet carries ICMP payload, it should be properly dispatched. Otherwise, discarded
            (a proper ICMP error response is NOT required for this project). */

            if (ip_h->ip_tos != ip_protocol_icmp) {
                printf("Received non-ICMP payload\n");
                return;
            }

            printf("Received ICMP payload\n");

            #pragma region //
        }
        else {
            /* For (2), your router should use the longest prefix match algorithm to find a next-hop IP ad-
            dress in the routing table and attempt to forward it there */

            #pragma region // find next-hop
                RoutingTableEntry next_hop;
                try {
                    next_hop = m_routingTable.lookup(ip_h->ip_dst);
                } catch (...) {
                    printf("Lookup failed\n");
                    return;
                }
            #pragma endregion

            /* For each forwarded IPv4 packet, your router should correctly decrement TTL and recompute the
            checksum. */
            #pragma region // decrement TTL
                // Don't forward if TTL = 0
                if (ip_h->ip_ttl == 0) {
                    printf("TTL = 0\n");
                    ICMP2 icmp;
                    #define ICMP_TIME_EXCEEDED 11
                    icmp.type = ICMP_TIME_EXCEEDED;
                    icmp.code = 0;
                    memcpy(icmp.data, ip_h, sizeof(ip_hdr));
                    memcpy(icmp.data + sizeof(ip_hdr), ip_data.data(), 64); 
                    return;
                }
                printf("Decrementing TTL\n");
                ip_h->ip_ttl -= 1;
            #pragma endregion
            #pragma region // recompute checksum
                // copy header excluding old checksum
                #define HDR_LESS_CKSUM_LEN 18
                uint8_t* hdr_less_cksum[HDR_LESS_CKSUM_LEN];
                #define BYTES_BEFORE_CKSUM 9
                #define BYTES_AFTER_CKSUM 8
                memcpy(hdr_less_cksum, ip_h, BYTES_BEFORE_CKSUM);
                memcpy(hdr_less_cksum + BYTES_BEFORE_CKSUM + sizeof(ip_h->ip_sum),
                    ip_h + BYTES_BEFORE_CKSUM + sizeof(ip_h->ip_sum),
                    BYTES_AFTER_CKSUM
                );
                // recalculate checksum and assign to original header
                ip_h->ip_sum = cksum(hdr_less_cksum, HDR_LESS_CKSUM_LEN);
            #pragma endregion
        

            std::shared_ptr<ArpEntry> arp_entry = m_arp.lookup(next_hop.dest);
            if (arp_entry == nullptr) {
                ;
            } else {
                mac_cpy(ether_hdr->ether_dhost, arp_entry->mac.data());
            }
            mac_cpy(ether_hdr->ether_shost, iface->addr.data());

            sendPacket(packet, next_hop.ifName);

        }
        ////////////////////////////////////////// END 2.3 IPv4 PACKETS ////////////////////////////////////////////////


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
