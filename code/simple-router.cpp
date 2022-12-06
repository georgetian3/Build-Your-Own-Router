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


bool mac_eq(const uint8_t* a, const uint8_t* b) {
    return !memcmp(a, b, ETHER_ADDR_LEN);
}


namespace simple_router {

static const uint8_t BroadcastEtherAddr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD


void SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface) {
    print_section("handlePacket");
    printIfaces(std::cerr);
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
    print_hdrs(packet);

    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
    }

    // FILL THIS IN

    if (packet.size() < sizeof(ethernet_hdr)) {
        std::cerr << "Ethernet header too short, ignore" << std::endl;
        return;
    }        

    if (macToString(packet) != "ff:ff:ff:ff:ff:ff" &&
        macToString(packet) != macToString(iface->addr)) {
        std::cerr << "Ethernet dest MAC addr != iface/broadcast, ignore" << std::endl;
        return;
    }
    
    auto ether_h = get_ether_h(packet);

    if (ntohs(ether_h->ether_type) == ethertype_arp)
    {
        std::cerr << "Handling ARP packet" << std::endl;
        if (packet.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr)) // Packet size is smaller than required, ignore
        {
            std::cerr << "Invalid packet size, too small for ARP, ignoring" << std::endl;
            return;
        }
        arp_hdr *arp_head = const_cast<arp_hdr *>(reinterpret_cast<const arp_hdr *>((packet.data() + sizeof(ethernet_hdr)))); // Get the ARP header by getting the memory starting past the ethernet header
        uint16_t op_type = ntohs(arp_head->arp_op);
        if (op_type == arp_op_request) // ARP request, 0x0001 in hex
        {
            std::cerr << "Handling ARP request" << std::endl;
            if (arp_head->arp_tip != iface->ip) // ARP IP not equal to interface IP, drop it
            {
                std::cerr << "Invalid packet, ARP IP and interface IP not equal, ignoring" << std::endl;
                return;
            }
            Buffer buf(sizeof(ethernet_hdr) + sizeof(arp_hdr)); // Buffer for reply packet
            ethernet_hdr *reply_eth_head = reinterpret_cast<ethernet_hdr *>(buf.data());
            ;                                                                                         // Reserve memory for ethernet header
            arp_hdr *reply_arp_head = reinterpret_cast<arp_hdr *>(buf.data() + sizeof(ethernet_hdr)); // Reserve memory after ethernet header for ARP header
            // Construct ethernet header
            memcpy(reply_eth_head->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);   // Copy interface to be source
            memcpy(reply_eth_head->ether_dhost, &(arp_head->arp_sha), ETHER_ADDR_LEN); // Copy ARP frame for dest
            reply_eth_head->ether_type = htons(ethertype_arp);
            // Construct ARP header, mostly copy from existing, swap destination and sources
            reply_arp_head->arp_hrd = htons(ETHER_ADDR_LEN);
            reply_arp_head->arp_pro = htons(ethertype_ip);
            reply_arp_head->arp_hln = ETHER_ADDR_LEN;
            reply_arp_head->arp_pln = 4;
            reply_arp_head->arp_op = htons(arp_op_reply);                          // Reply opcode, switch endianness of bytes
            reply_arp_head->arp_sip = iface->ip;                                   // Switch source and dest
            reply_arp_head->arp_tip = arp_head->arp_sip;                           // Switch source and dest
            memcpy(reply_arp_head->arp_tha, &(arp_head->arp_sha), ETHER_ADDR_LEN); // Switch source and dest
            memcpy(reply_arp_head->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);   // Switch source and dest
            std::cerr << "Created ARP reply in response of request" << std::endl;
            sendPacket(buf, iface->name); // Send the created reply packet
        }
        else if (op_type == arp_op_reply) // ARP reply, 0x0002 in hex
        {
            std::cerr << "Handling ARP reply" << std::endl;
            Buffer mBuf(ETHER_ADDR_LEN);                                 // Buffer for MAC/IP combo to insert into the ARP cache
            uint8_t *mac_ptr = reinterpret_cast<uint8_t *>(mBuf.data()); // Pointer to the buffer
            memcpy(mac_ptr, arp_head->arp_sha, ETHER_ADDR_LEN);
            auto arpReqEntry = m_arp.insertArpEntry(mBuf, (uint32_t)(arp_head->arp_sip));
            if (arpReqEntry != nullptr) // && !arpReqEntry->packets.empty()) //All good to forward
            {
                for (auto p = arpReqEntry->packets.begin(); p != arpReqEntry->packets.end(); ++p)
                { // Forward individual packets from ARP reply
                    std::cerr << "Forwarding packet in ARP reply" << std::endl;
                    std::string iname = p->iface;
                    Buffer pend = p->packet; // Buffer to store headers
                    ethernet_hdr *pend_eth_head = reinterpret_cast<ethernet_hdr *>(pend.data());
                    memcpy(pend_eth_head->ether_dhost, mac_ptr, ETHER_ADDR_LEN);
                    memcpy(pend_eth_head->ether_shost, findIfaceByName(iname), ETHER_ADDR_LEN);
                    ip_hdr *pend_ip_h = reinterpret_cast<ip_hdr *>(pend.data() + sizeof(ethernet_hdr));
                    pend_ip_h->ip_ttl -= 1;
                    pend_ip_h->ip_sum = 0;
                    pend_ip_h->ip_sum = cksum(pend_ip_h, ntohs(pend_ip_h->ip_len));
                    sendPacket(pend, iname);
                }
                m_arp.removeRequest(arpReqEntry); // We've finished it, so remove it
            }
            else
            {
                std::cerr << "Error in queueing packet, not queued, therefore ignoring" << std::endl;
                return;
            }
        }
        else // Neither ARP request or reply, ignore
        {
            std::cerr << "ARP opcode is neither request or reply, ignoring" << std::endl;
            return;
        }
    }
    else if (ntohs(ether_h->ether_type) == ethertype_ip)
    {
        std::cerr << "Received IP packet" << std::endl;

        auto ip_h = get_ip_h(packet);
        if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) {
            std::cerr << "IP header too short, ignore" << std::endl;
            return;
        }

        uint16_t old_sum = ip_h->ip_sum;
        ip_h->ip_sum = 0;
        if (cksum(ip_h, sizeof(ip_hdr)) != old_sum) {
            std::cerr << "IP checksum incorrect, ignore" << std::endl;
            return;
        }

        bool ip_to_router = false;
        for (const auto& iface: m_ifaces) {
            if (iface.ip == ip_h->ip_dst) {
                ip_to_router = true;
                break;
            }
        }

        /* Your router should classify datagrams into (1) destined to the router (to one of the IP addresses of
        the router), and (2) datagrams to be forwarded: */
        if (ip_to_router) {
            /* For (1), if packet carries ICMP payload, it should be properly dispatched. Otherwise, discarded
            (a proper ICMP error response is NOT required for this project). */
            std::cerr << "IP to router" << std::endl;
            if (ip_h->ip_p != ip_protocol_icmp) {
                std::cerr << "Received non-ICMP, ignore" << std::endl;
                return;
            }
            std::cerr << "Received ICMP" << std::endl;

            auto icmp_h = get_icmp_h(packet);

            if (icmp_h->icmp_type != 8) { // if not echo request
                std::cerr << "ICMP type unknown" << std::endl;
                return;
            }

            set_icmp_h(get_icmp_h(packet), echo_reply);
            set_ip_h(get_ip_h(packet), sizeof(ip_hdr) + sizeof(icmp_hdr), 64, ip_protocol_icmp, iface->ip, ip_h->ip_src);

            auto arp_entry = m_arp.lookup(ip_h->ip_dst);
            if (arp_entry == nullptr) {
                std::cerr << "Destination MAC unknown" << std::endl;
                Buffer arp_request(sizeof(ethernet_hdr) + sizeof(arp_hdr));
                set_arp_h(get_arp_h(arp_request), arp_op_request, iface->ip, ip_h->ip_dst, iface->addr.data(), nullptr);
                set_ether_h(get_ether_h(arp_request), ethertype_arp, iface->addr.data(), nullptr);
                std::cerr << "Sending ARP request" << std::endl;
                sendPacket(arp_request, inIface);
                return;
            }
            
            set_ether_h(get_ether_h(packet), ethertype_ip, iface->addr.data(), arp_entry->mac.data());
            std::cerr << "Sending ICMP reply" << std::endl;
            sendPacket(packet, inIface);
            return;
        }


        std::cerr << "IP to forward" << std::endl;

        if (ip_h->ip_ttl == 0) {
            std::cerr << "TTL = 0, ignore" << std::endl;
            return; 
        }

        set_ip_h(ip_h, ip_h->ip_len, ip_h->ip_ttl - 1, ip_h->ip_p, ip_h->ip_src, ip_h->ip_dst);

        std::cerr << "Forwarding IPv4 packet" << std::endl;
        RoutingTableEntry next_hop;
        try {
            next_hop = m_routingTable.lookup(ip_h->ip_dst);
        } catch (...) {
            std::cerr << "Next hop lookup failed" << std::endl;
            return;
        }
        auto outIface = findIfaceByName(next_hop.ifName);
        auto arp_entry = m_arp.lookup(next_hop.dest);
        if (arp_entry == nullptr) {
            std::cerr << "Next hop MAC unknown" << std::endl;
            m_arp.queueRequest(next_hop.gw, packet, next_hop.ifName);
            Buffer arp_request(sizeof(ethernet_hdr) + sizeof(arp_hdr));
            arp_hdr *arp_req_head = reinterpret_cast<arp_hdr *>(arp_request.data() + sizeof(ethernet_hdr));
            set_arp_h(get_arp_h(arp_request), arp_op_request, outIface->ip, next_hop.gw, outIface->addr.data(), nullptr);
            set_ether_h(get_ether_h(arp_request), ethertype_arp, outIface->addr.data(), nullptr);
            sendPacket(arp_request, outIface->name);
        } else {
            set_ether_h(get_ether_h(packet), ethertype_ip, iface->addr.data(), arp_entry->mac.data());
            std::cerr << "Forwarding packet" << std::endl;
            sendPacket(packet, next_hop.ifName);
        }
    } else {
        // Your router should ignore Ethernet frames other than ARP and IPv4.
        std::cerr << "Unrecognized ethernet type" << std::endl;
    }
}

void
SimpleRouter::handlePacket2(const Buffer& packet, const std::string& inIface)
{
    print_section("handlePacket");
    std::cerr << getRoutingTable() << std::endl;
    printIfaces(std::cerr);
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
    print_hdrs(packet);

    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
    }

    // FILL THIS IN

    if (packet.size() < sizeof(ethernet_hdr)) {
        std::cerr << "Ethernet header too short, ignore" << std::endl;
        return;
    }        

    if (macToString(packet) != "ff:ff:ff:ff:ff:ff" &&
        macToString(packet) != macToString(iface->addr)) {
        std::cerr << "Ethernet dest MAC addr != iface/broadcast, ignore" << std::endl;
        return;
    }
    
    auto ether_h = get_ether_h(packet);
    if (ntohs(ether_h->ether_type) == ethertype_arp) {
    std::cerr << "Handling ARP packet" << std::endl;
    if (packet.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr)) //Packet size is smaller than required, ignore
    {
      std::cerr << "Invalid packet size, too small for ARP, ignoring" << std::endl;
      return;
    }
    arp_hdr *arp_head = const_cast<arp_hdr *>(reinterpret_cast<const arp_hdr *>((packet.data() + sizeof(ethernet_hdr)))); //Get the ARP header by getting the memory starting past the ethernet header
    uint16_t op_type = ntohs(arp_head -> arp_op);
    if (op_type == arp_op_request) //ARP request, 0x0001 in hex
    {
      std::cerr << "Handling ARP request" << std::endl;
      if (arp_head -> arp_tip != iface -> ip) //ARP IP not equal to interface IP, drop it
      {
        std::cerr << "Invalid packet, ARP IP and interface IP not equal, ignoring" << std::endl;
        return;
      }
      Buffer buf(sizeof(ethernet_hdr) + sizeof(arp_hdr)); //Buffer for reply packet
      ethernet_hdr * reply_eth_head = reinterpret_cast<ethernet_hdr *>(buf.data());; //Reserve memory for ethernet header
      arp_hdr * reply_arp_head = reinterpret_cast<arp_hdr *>(buf.data()+ sizeof(ethernet_hdr)); //Reserve memory after ethernet header for ARP header
      //Construct ethernet header
      memcpy(reply_eth_head -> ether_shost, iface -> addr.data(), ETHER_ADDR_LEN); //Copy interface to be source
      memcpy(reply_eth_head -> ether_dhost, &(arp_head -> arp_sha), ETHER_ADDR_LEN); //Copy ARP frame for dest
      reply_eth_head -> ether_type = htons(ethertype_arp);
      //Construct ARP header, mostly copy from existing, swap destination and sources
      reply_arp_head -> arp_hrd = htons(ETHER_ADDR_LEN);
      reply_arp_head -> arp_pro = htons(ethertype_ip);
      reply_arp_head -> arp_hln = ETHER_ADDR_LEN;
      reply_arp_head -> arp_pln = 4;
      reply_arp_head -> arp_op = htons(arp_op_reply); //Reply opcode, switch endianness of bytes
      reply_arp_head -> arp_sip = iface -> ip; //Switch source and dest
      reply_arp_head -> arp_tip = arp_head -> arp_sip; //Switch source and dest
      memcpy(reply_arp_head -> arp_tha, &(arp_head -> arp_sha), ETHER_ADDR_LEN); //Switch source and dest
      memcpy(reply_arp_head -> arp_sha, iface -> addr.data(), ETHER_ADDR_LEN); //Switch source and dest
      std::cerr << "Created ARP reply in response of request" << std::endl;
      sendPacket(buf, iface->name); //Send the created reply packet
    }
    else if (op_type == arp_op_reply) //ARP reply, 0x0002 in hex
    {
      std::cerr << "Handling ARP reply" << std::endl;
      Buffer mBuf(ETHER_ADDR_LEN); //Buffer for MAC/IP combo to insert into the ARP cache
      uint8_t * mac_ptr = reinterpret_cast<uint8_t *>(mBuf.data()); //Pointer to the buffer
      memcpy(mac_ptr, arp_head -> arp_sha, ETHER_ADDR_LEN);
      auto arpReqEntry = m_arp.insertArpEntry(mBuf, (uint32_t) (arp_head -> arp_sip));
      if (arpReqEntry != nullptr) // && !arpReqEntry->packets.empty()) //All good to forward
      {
        for (auto p = arpReqEntry->packets.begin(); p != arpReqEntry->packets.end(); ++p)
        { //Forward individual packets from ARP reply
          std::cerr << "Forwarding packet in ARP reply" << std::endl;
          std::string iname = p -> iface;
          Buffer pend = p -> packet; //Buffer to store headers
          ethernet_hdr * pend_eth_head = reinterpret_cast<ethernet_hdr *>(pend.data());
          memcpy(pend_eth_head -> ether_dhost, mac_ptr, ETHER_ADDR_LEN);
          memcpy(pend_eth_head -> ether_shost, findIfaceByName(iname), ETHER_ADDR_LEN);
          ip_hdr * pend_ip_h = reinterpret_cast<ip_hdr *>(pend.data() + sizeof(ethernet_hdr));
          pend_ip_h -> ip_ttl -= 1;
          pend_ip_h -> ip_sum = 0;
          pend_ip_h -> ip_sum = cksum(pend_ip_h, ntohs(pend_ip_h -> ip_len));
          sendPacket(pend, iname);
        }
        m_arp.removeRequest(arpReqEntry); //We've finished it, so remove it
      }
      else
      {
        std::cerr << "Error in queueing packet, not queued, therefore ignoring" << std::endl;
        return;
      }
    }
    else //Neither ARP request or reply, ignore
    {
      std::cerr << "ARP opcode is neither request or reply, ignoring" << std::endl;
      return;
    }
  }
    
    
    
    
    
    
    
    
    
    
    
    
    else if (ntohs(ether_h->ether_type) == ethertype_ip) {
        std::cerr << "Received IP packet" << std::endl;

        auto ip_h = get_ip_h(packet);
        if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) {
            std::cerr << "IP header too short, ignore" << std::endl;
            return;
        }

        uint16_t old_sum = ip_h->ip_sum;
        ip_h->ip_sum = 0;
        if (cksum(ip_h, sizeof(ip_hdr)) != old_sum) {
            std::cerr << "IP checksum incorrect, ignore" << std::endl;
            return;
        }

        bool ip_to_router = false;
        for (const auto& iface: m_ifaces) {
            if (iface.ip == ip_h->ip_dst) {
                ip_to_router = true;
                break;
            }
        }

        if (ip_to_router) {
            /* For (1), if packet carries ICMP payload, it should be properly dispatched. Otherwise, discarded
                (a proper ICMP error response is NOT required for this project). */
            std::cerr << "IP to router" << std::endl;
            auto ip_h = get_ip_h(packet);
            if (ip_h->ip_p != ip_protocol_icmp) {
                std::cerr << "Received non-ICMP, ignore" << std::endl;
                return;
            }
            std::cerr << "Received ICMP" << std::endl;

            auto icmp_h = get_icmp_h(packet);

            if (icmp_h->icmp_type != 8) { // if not echo request
                std::cerr << "ICMP type unknown" << std::endl;
                return;
            }

            set_icmp_h(get_icmp_h(packet), echo_reply);
            set_ip_h(get_ip_h(packet), sizeof(ip_hdr) + sizeof(icmp_hdr), 64, ip_protocol_icmp, iface->ip, ip_h->ip_src);

            auto arp_entry = m_arp.lookup(ip_h->ip_dst);
            if (arp_entry == nullptr) {
                std::cerr << "Destination MAC unknown" << std::endl;
                Buffer arp_request(sizeof(ethernet_hdr) + sizeof(arp_hdr));
                set_arp_h(get_arp_h(arp_request), arp_op_request, iface->ip, ip_h->ip_dst, iface->addr.data(), nullptr);
                set_ether_h(get_ether_h(arp_request), ethertype_arp, iface->addr.data(), nullptr);
                std::cerr << "Sending ARP request" << std::endl;
                sendPacket(arp_request, inIface);
                return;
            }
            
            set_ether_h(get_ether_h(packet), ethertype_ip, iface->addr.data(), arp_entry->mac.data());
            std::cerr << "Sending ICMP reply" << std::endl;
            sendPacket(packet, inIface);
            return;
        }
        


        set_ip_h(ip_h, ip_h->ip_len, ip_h->ip_ttl - 1, ip_h->ip_p, ip_h->ip_src, ip_h->ip_dst);


        RoutingTableEntry next_hop;
        try {
            next_hop = m_routingTable.lookup(ip_h->ip_dst);
        } catch (...) {
            std::cerr << "Next hop lookup failed" << std::endl;
            return;
        }
        auto outIface = findIfaceByName(next_hop.ifName);
        auto arp_entry = m_arp.lookup(next_hop.gw);
        if (arp_entry == nullptr) {
            std::cerr << "Next hop MAC unknown" << std::endl;
            m_arp.queueRequest(next_hop.gw, packet, next_hop.ifName);
            Buffer arp_request(sizeof(ethernet_hdr) + sizeof(arp_hdr));
            set_arp_h(get_arp_h(arp_request), arp_op_request, outIface->ip, next_hop.gw, outIface->addr.data(), nullptr);
            set_ether_h(get_ether_h(arp_request), ethertype_arp, iface->addr.data(), nullptr);
            std::cerr << "Sending ARP request" << std::endl;
            sendPacket(arp_request, next_hop.ifName);
        } else {
            set_ether_h(get_ether_h(packet), ethertype_ip, iface->addr.data(), arp_entry->mac.data());
            std::cerr << "Forwarding packet" << std::endl;
            sendPacket(packet, next_hop.ifName);
        }
    } else {
        // Your router should ignore Ethernet frames other than ARP and IPv4.
        std::cerr << "Unrecognized ethernet type" << std::endl;
    }

}

void
SimpleRouter::handlePacket1(const Buffer& packet, const std::string& inIface)
{

    print_section("handlePacket");
    std::cerr << getRoutingTable() << std::endl;
    printIfaces(std::cerr);
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
    print_hdrs(packet);

    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
    }

    // FILL THIS IN

    if (packet.size() < sizeof(ethernet_hdr)) {
        std::cerr << "Ethernet header too short, ignore" << std::endl;
        return;
    }        

    if (macToString(packet) != "ff:ff:ff:ff:ff:ff" &&
        macToString(packet) != macToString(iface->addr)) {
        std::cerr << "Ethernet dest MAC addr != iface/broadcast, ignore" << std::endl;
        return;
    }
    
    auto ether_h = get_ether_h(packet);

    if (ntohs(ether_h->ether_type) == ethertype_arp) {
        std::cerr << "Received ARP packet" << std::endl;

        if (packet.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr)) {
            std::cerr << "ARP packet too short, ignore" << std::endl;
            return;
        }

        auto arp_h = get_arp_h(packet);
        if (ntohs(arp_h->arp_op) == arp_op_request) {
            std::cerr << "Received ARP request" << std::endl;
            if (arp_h->arp_tip != iface->ip) {
                std::cerr << "ARP dest IP != iface IP, ignore" << std::endl;
                return;
            }
            set_arp_h(arp_h, arp_op_reply, iface->ip, arp_h->arp_sip, iface->addr.data(), arp_h->arp_sha);
            set_ether_h(ether_h, ethertype_arp, arp_h->arp_sha, arp_h->arp_tha);
            std::cerr << "Sending ARP reply" << std::endl;
            sendPacket(packet, iface->name);
            return;
        } else if (ntohs(arp_h->arp_op) == arp_op_reply) {
            std::cerr << "Received ARP reply" << std::endl;
            Buffer arp_sha(ETHER_ADDR_LEN);
            memcpy(arp_sha.data(), arp_h->arp_sha, ETHER_ADDR_LEN);
            auto arp_requests = m_arp.insertArpEntry(arp_sha, arp_h->arp_sip);
            if (arp_requests == nullptr) {
                std::cerr << "No packets waiting for ARP reply" << std::endl;
            } else {
                for (auto it = arp_requests->packets.begin(); it != arp_requests->packets.end(); ++it) {
                    Buffer packet = it->packet;
                    auto p_ether_h = get_ether_h(packet);
                    set_ether_h(p_ether_h, (enum ethertype)p_ether_h->ether_type, iface->addr.data(), arp_h->arp_sha);
                    sendPacket(packet, it->iface);
                }
                m_arp.removeRequest(arp_requests);
            }
        } else {
            std::cerr << "ARP opcode unknown, ignore" << std::endl;
            return;
        }
    } else if (ntohs(ether_h->ether_type) == ethertype_ip) {
        std::cerr << "Received IP packet" << std::endl;

        auto ip_h = get_ip_h(packet);
        if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) {
            std::cerr << "IP header too short, ignore" << std::endl;
            return;
        }

        uint16_t old_sum = ip_h->ip_sum;
        ip_h->ip_sum = 0;
        if (cksum(ip_h, sizeof(ip_hdr)) != old_sum) {
            std::cerr << "IP checksum incorrect, ignore" << std::endl;
            return;
        }

        bool ip_to_router = false;
        for (const auto& iface: m_ifaces) {
            if (iface.ip == ip_h->ip_dst) {
                ip_to_router = true;
                break;
            }
        }

        /* Your router should classify datagrams into (1) destined to the router (to one of the IP addresses of
        the router), and (2) datagrams to be forwarded: */
        if (ip_to_router) {
            /* For (1), if packet carries ICMP payload, it should be properly dispatched. Otherwise, discarded
            (a proper ICMP error response is NOT required for this project). */
            std::cerr << "IP to router" << std::endl;
            if (ip_h->ip_p != ip_protocol_icmp) {
                std::cerr << "Received non-ICMP, ignore" << std::endl;
                return;
            }
            std::cerr << "Received ICMP" << std::endl;

            auto icmp_h = get_icmp_h(packet);

            if (icmp_h->icmp_type != 8) { // if not echo request
                std::cerr << "ICMP type unknown" << std::endl;
                return;
            }

            set_icmp_h(get_icmp_h(packet), echo_reply);
            set_ip_h(get_ip_h(packet), sizeof(ip_hdr) + sizeof(icmp_hdr), 64, ip_protocol_icmp, iface->ip, ip_h->ip_src);

            auto arp_entry = m_arp.lookup(ip_h->ip_dst);
            if (arp_entry == nullptr) {
                std::cerr << "Destination MAC unknown" << std::endl;
                Buffer arp_request(sizeof(ethernet_hdr) + sizeof(arp_hdr));
                set_arp_h(get_arp_h(arp_request), arp_op_request, iface->ip, ip_h->ip_dst, iface->addr.data(), nullptr);
                set_ether_h(get_ether_h(arp_request), ethertype_arp, iface->addr.data(), nullptr);
                std::cerr << "Sending ARP request" << std::endl;
                sendPacket(arp_request, inIface);
                return;
            }
            
            set_ether_h(get_ether_h(packet), ethertype_ip, iface->addr.data(), arp_entry->mac.data());
            std::cerr << "Sending ICMP reply" << std::endl;
            sendPacket(packet, inIface);
            return;
        } else {
            std::cerr << "IP to forward" << std::endl;

            

            if (ip_h->ip_ttl == 0) {
                std::cerr << "TTL = 0, ignore" << std::endl;
                /* icmp_hdr icmp_h;
                set_icmp_h(&icmp_h, time_exceeded);
                Buffer response(packet);
                response.resize(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr), 0);
                memmove(response.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), (const void*)&icmp_h, sizeof(icmp_hdr));
                set_ip_h(get_ip_h(response), sizeof(ip_hdr) + sizeof(icmp_hdr), ip_h->ip_ttl - 1, ip_protocol_icmp, iface->ip, ip_h->ip_src);

                auto arp_entry = m_arp.lookup(ip_h->ip_src);
                if (arp_entry == nullptr) {
                    m_arp.queueRequest(ip_h->ip_src, response, inIface);
                } else {
                    set_ether_h(get_ether_h(response), ethertype_ip, iface->addr.data(), arp_entry->mac.data());
                    sendPacket(packet, inIface);
                } */
                return; 
            }


            set_ip_h(ip_h, packet.size(), ip_h->ip_ttl - 1, ip_h->ip_p, ip_h->ip_src, ip_h->ip_dst);


            RoutingTableEntry next_hop;
            try {
                next_hop = m_routingTable.lookup(ip_h->ip_dst);
            } catch (...) {
                std::cerr << "Next hop lookup failed" << std::endl;
                return;
            }
            auto outIface = findIfaceByName(next_hop.ifName);
            auto arp_entry = m_arp.lookup(next_hop.dest);
            if (arp_entry == nullptr) {
                std::cerr << "Next hop MAC unknown" << std::endl;
                m_arp.queueRequest(next_hop.gw, packet, next_hop.ifName);
                Buffer arp_request(sizeof(ethernet_hdr) + sizeof(arp_hdr));
                set_arp_h(get_arp_h(arp_request), arp_op_request, findIfaceByName(next_hop.ifName)->ip, next_hop.gw, iface->addr.data(), nullptr);
                set_ether_h(get_ether_h(arp_request), ethertype_arp, iface->addr.data(), nullptr);
                sendPacket(arp_request, next_hop.ifName);
            } else {
                set_ether_h(get_ether_h(packet), ethertype_ip, iface->addr.data(), arp_entry->mac.data());
                std::cerr << "Forwarding packet" << std::endl;
                sendPacket(packet, next_hop.ifName);
            }


        }

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
    
    print_section("BEGIN sendPacket");
    print_hdrs(packet);
    print_section("END sendPacket");


    
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
