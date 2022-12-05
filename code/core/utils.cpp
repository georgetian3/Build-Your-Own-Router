/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017 Alexander Afanasyev
 * Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "utils.hpp"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


namespace simple_router {

uint16_t
cksum(const void* _data, int len)
{
  const uint8_t* data = reinterpret_cast<const uint8_t*>(_data);
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(const uint8_t* buf) {
  ethernet_hdr *ehdr = (ethernet_hdr *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(const uint8_t* buf) {
  ip_hdr *iphdr = (ip_hdr *)(buf);
  return iphdr->ip_p;
}


std::string
macToString(const Buffer& macAddr)
{
  char s[18]; // 12 digits + 5 separators + null terminator
  char sep = ':';

  // - apparently gcc-4.6 does not support the 'hh' type modifier
  // - std::snprintf not found in some environments
  //   https://redmine.named-data.net/issues/2299 for more information
  snprintf(s, sizeof(s), "%02x%c%02x%c%02x%c%02x%c%02x%c%02x",
           macAddr.at(0), sep, macAddr.at(1), sep, macAddr.at(2), sep,
           macAddr.at(3), sep, macAddr.at(4), sep, macAddr.at(5));

  return std::string(s);
}

std::string
ipToString(uint32_t ip)
{
  in_addr addr;
  addr.s_addr = ip;
  return ipToString(addr);
}

std::string
ipToString(const in_addr& address)
{
  char s[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, s, INET_ADDRSTRLEN) == nullptr) {
    throw std::runtime_error("Error while converting IP address to string");
  }
  return std::string(s);
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(const uint8_t* addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

void print_addr_ip_int(uint32_t ip)
{
  in_addr addr;
  addr.s_addr = ntohl(ip);
  print_addr_ip(addr);
}

/* Prints out fields in Ethernet header. */
void
print_hdr_eth(const uint8_t* buf) {
  const ethernet_hdr *ehdr = (const ethernet_hdr *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(const uint8_t* buf) {
  const ip_hdr *iphdr = (const ip_hdr *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(const uint8_t* buf) {
  const icmp_hdr *hdr = reinterpret_cast<const icmp_hdr*>(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(const uint8_t* buf) {
  const arp_hdr *hdr = reinterpret_cast<const arp_hdr*>(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(hdr->arp_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(hdr->arp_pro));
  fprintf(stderr, "\thardware address length: %d\n", hdr->arp_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", hdr->arp_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(hdr->arp_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(hdr->arp_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(hdr->arp_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(hdr->arp_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(hdr->arp_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(const uint8_t* buf, uint32_t length) {

  /* Ethernet */
  size_t minlength = sizeof(ethernet_hdr);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(ip_hdr);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(ethernet_hdr));
    uint8_t ip_proto = ip_protocol(buf + sizeof(ethernet_hdr));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(icmp_hdr);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(arp_hdr);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(ethernet_hdr));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

void print_hdrs(const Buffer& buffer)
{
  print_hdrs(buffer.data(), buffer.size());
}



ethernet_hdr* get_ether_h(const Buffer& packet) {
    return (ethernet_hdr*)packet.data();
}
arp_hdr* get_arp_h(const Buffer& packet) {
    return (arp_hdr*)(packet.data() + sizeof(ethernet_hdr));
}
ip_hdr* get_ip_h(const Buffer& packet) {
    return (ip_hdr*)(packet.data() + sizeof(ethernet_hdr));
}
icmp_hdr* get_icmp_h(const Buffer& packet) {
    return (icmp_hdr*)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
}

void set_ether_h(ethernet_hdr* ether_h, enum ethertype type, const uint8_t* shost, const uint8_t* dhost) {
    ether_h->ether_type = ntohs(type);

    uint8_t shost_old[ETHER_ADDR_LEN];
    if (dhost == ether_h->ether_shost) {
        memcpy((void*)shost_old, ether_h->ether_shost, ETHER_ADDR_LEN);
        dhost = shost_old;
    }
    memmove(ether_h->ether_shost, shost, ETHER_ADDR_LEN);
    if (dhost == nullptr) {
        memset(ether_h->ether_dhost, 0, ETHER_ADDR_LEN);
    } else {
        memmove(ether_h->ether_dhost, dhost, ETHER_ADDR_LEN);
    }
}


void set_arp_h(arp_hdr* arp_h, const arp_opcode opcode, const uint32_t sip, const uint32_t tip, const uint8_t* sha, const uint8_t* tha) {
    arp_h->arp_hrd = ntohs(arp_hrd_ethernet);
    arp_h->arp_pro = ntohs(ethertype_ip);
    arp_h->arp_hln = ETHER_ADDR_LEN;
    arp_h->arp_pln = sizeof(uint32_t);
    arp_h->arp_op = ntohs(opcode);
    arp_h->arp_sip = sip;
    arp_h->arp_tip = tip;
    
    uint8_t sha_old[ETHER_ADDR_LEN];
    if (tha == arp_h->arp_sha) {
        memcpy((void*)sha_old, arp_h->arp_sha, ETHER_ADDR_LEN);
        tha = sha_old;
    }
    memmove(arp_h->arp_sha, sha, ETHER_ADDR_LEN);
    if (tha == nullptr) {
        memset(arp_h->arp_tha, 0, ETHER_ADDR_LEN);
    } else {
        memmove(arp_h->arp_tha, tha, ETHER_ADDR_LEN);
    }
}

void set_ip_h(ip_hdr* ip_h, const uint16_t len, const uint8_t ttl, const uint8_t protocol, const uint32_t ip_src, const uint32_t ip_dst) {
    ip_h->ip_len = len;
    ip_h->ip_ttl = ttl;
    ip_h->ip_p   = protocol;
    ip_h->ip_sum = 0;
    ip_h->ip_src = ip_src;
    ip_h->ip_dst = ip_dst;
    ip_h->ip_sum = cksum(ip_h, sizeof(ip_hdr));
}

void set_icmp_h(icmp_hdr* icmp_h, icmp_type type) {
    if (type == echo_reply) {
        icmp_h->icmp_type = 0;
    } else if (type == time_exceeded) {
        icmp_h->icmp_type = 11;
        icmp_h->icmp_code = 0;
    } else if (type == port_unreachable) {
        icmp_h->icmp_type = 3;
        icmp_h->icmp_code = 3;
    }
    icmp_h->icmp_sum = 0;
    icmp_h->icmp_sum = cksum(icmp_h, sizeof(icmp_h));
}

void print_section(const ::std::string& section, char c) {
    int n = 80 - 2 - section.length();

    ::std::string half = ::std::string(n / 2, c);

    std::cout << half;
    if (n % 2) {
        std::cout << c;
    }
    std::cout << ' ' << section << ' ' << half << '\n';
}

    

} // namespace simple_router
