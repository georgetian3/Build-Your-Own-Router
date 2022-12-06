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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

    // FILL THIS IN
    //print_section("BEGIN CheckArp");
    
    const Interface* outIface;
    for (auto arp_request_it = m_arpRequests.begin(); arp_request_it != m_arpRequests.end(); ++arp_request_it) {
        auto arp_request = *arp_request_it;
        if (steady_clock::now() - arp_request->timeSent <= seconds(1)) {
            continue;
        }
        if (arp_request->nTimesSent >= MAX_SENT_TIME) {

            for (const auto& q_packet: arp_request->packets) {

                Buffer packet_out(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr));
                set_icmp_h(get_icmp_h(packet_out), port_unreachable, packet_out.size());

                
                outIface = m_router.findIfaceByName(q_packet.iface);

                auto ip_h = get_ip_h(packet_out);
                set_ip_h(ip_h, sizeof(ip_hdr) + sizeof(icmp_hdr), 64, ip_protocol_icmp, 
                    outIface->ip, outIface->ip //get_ip_h(q_packet->packet)->ip_dst
                );
                set_ether_h(get_ether_h(packet_out), ethertype_ip, outIface->addr.data(), get_ether_h(q_packet.packet)->ether_shost);
                std::cout << "Send host unreachable\n";
                m_router.sendPacket(packet_out, outIface->name);
            }
            removeRequest(arp_request);
        } else {
            Buffer packet_out(sizeof(ethernet_hdr) + sizeof(arp_hdr));
            arp_request->timeSent = steady_clock::now();
            arp_request->nTimesSent++;
            std::cout << "Resending ARP request\n";
            return;
            outIface = m_router.findIfaceByName(arp_request->packets.front().iface);
            set_arp_h(get_arp_h(packet_out), arp_op_request, outIface->ip, arp_request->ip, outIface->addr.data(), nullptr);
            set_ether_h(get_ether_h(packet_out), ethertype_arp, outIface->addr.data(), nullptr);

            m_router.sendPacket(packet_out, outIface->name);
        }
}

    // remove invalid cache entries
    for (auto it = m_cacheEntries.begin(); it != m_cacheEntries.end();) {
        if ((*it)->isValid) {
            ++it;
        } else {
            it = m_cacheEntries.erase(it);
        }
    }

    //print_section("END CheckArp");

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
