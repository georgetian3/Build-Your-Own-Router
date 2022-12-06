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

#ifndef SIMPLE_ROUTER_CORE_UTILS_HPP
#define SIMPLE_ROUTER_CORE_UTILS_HPP

#include "protocol.hpp"

#include <iostream> // ADDED


namespace simple_router {

uint16_t cksum(const void* data, int len);
uint16_t ethertype(const uint8_t* buf);
uint8_t ip_protocol(const uint8_t* buf);

/**
 * Get formatted Ethernet address, e.g. 00:11:22:33:44:55
 */
std::string
macToString(const Buffer& macAddr);

std::string
ipToString(uint32_t ip);

std::string
ipToString(const in_addr& address);

void print_hdr_eth(const uint8_t* buf);
void print_hdr_ip(const uint8_t* buf);
void print_hdr_icmp(const uint8_t* buf);
void print_hdr_arp(const uint8_t* buf);

/* prints all headers, starting from eth */
void print_hdrs(const uint8_t* buf, uint32_t length);

void print_hdrs(const Buffer& buffer);


// ADDED

enum icmp_msg {
    echo_reply,
    time_exceeded,
    port_unreachable,
};

ethernet_hdr*   get_ether_h(const Buffer& packet);
arp_hdr*        get_arp_h(const Buffer& packet);
ip_hdr*         get_ip_h(const Buffer& packet);
icmp_hdr*       get_icmp_h(const Buffer& packet);

void set_ether_h(ethernet_hdr* ether_h, const enum ethertype type, const uint8_t* shost, const uint8_t* dhost);
void set_arp_h(arp_hdr* arp_h, const arp_opcode opcode, const uint32_t sip, const uint32_t tip, const uint8_t* sha, const uint8_t* tha);
void set_ip_h(ip_hdr* ip_h, const uint16_t len, const uint8_t ttl, const uint8_t protocol, const uint32_t ip_src, const uint32_t ip_dst);
void set_icmp_h(icmp_hdr* icmp_h, icmp_msg type);
void print_section(const ::std::string& section, char c = '#');
void print_addr_eth(const uint8_t* addr);



} // namespace simple_router

#endif // SIMPLE_ROUTER_CORE_UTILS_HPP
