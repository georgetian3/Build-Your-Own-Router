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
void set_icmp_h(icmp_hdr* icmp_h, icmp_msg type, size_t len);
void print_section(const ::std::string& section, char c = '#');
void print_addr_eth(const uint8_t* addr);


Buffer make_buffer(const uint8_t* data, size_t len);
Buffer concat_buf(const Buffer& a, const Buffer& b);

class Ethernet {

private:

    ethernet_hdr m_h;
    Buffer m_data;

public:

    Ethernet() {}
    Ethernet(const Buffer& packet) {
        memcpy(&m_h, packet.data(), sizeof(ethernet_hdr));
        m_data = Buffer(packet.begin() + sizeof(ethernet_hdr), packet.end());
    }
    uint16_t get_type() const {
        return ntohs(m_h.ether_type);
    }
    void set_type(uint16_t type) {
        m_h.ether_type = ntohs(type);
    }
    Buffer get_src() const {
        Buffer buf(ETHER_ADDR_LEN);
        memcpy(buf.data(), m_h.ether_shost, ETHER_ADDR_LEN);
        return buf;
    }
    void set_src(const uint8_t* src) {
        if (src) {
            memcpy(m_h.ether_shost, src, ETHER_ADDR_LEN);
        }
    }
    Buffer get_dst() const {
        Buffer buf(ETHER_ADDR_LEN);
        memcpy(buf.data(), m_h.ether_shost, ETHER_ADDR_LEN);
        return buf;
    }
    void set_dst(const uint8_t* dst) {
        // set dst to 0 for broadcast
        if (dst) {
            memcpy(m_h.ether_dhost, dst, ETHER_ADDR_LEN);
        } else {
            memset(m_h.ether_dhost, 0xff, ETHER_ADDR_LEN);
        }
    }
    Buffer get_data() const {
        return m_data;
    }
    void set_data(Buffer data) {
        m_data = data;
    }
    Ethernet(uint16_t type, const uint8_t* src, uint8_t* dst, Buffer data) {
        set_type(type);
        set_src(src);
        set_dst(dst);
        set_data(data);
    }
    Buffer get_packet() {
        Buffer hdr(sizeof(ethernet_hdr));
        memcpy(hdr.data(), &m_h, sizeof(ethernet_hdr));
        return concat_buf(hdr, m_data);
    }
};







class ARP {

private:

    arp_hdr m_h;

    void set_defaults() {
        m_h.arp_hrd = htons(arp_hrd_ethernet);
        m_h.arp_pro = htons(ethertype_ip);
        m_h.arp_hln = ETHER_ADDR_LEN;
        m_h.arp_pln = sizeof(uint32_t);
    }

public:

    ARP() {
        set_defaults();
    }
    ARP(const Buffer& packet) {
        memcpy(&m_h, packet.data() + sizeof(ethernet_hdr), sizeof(arp_hdr));
    }
    unsigned short get_opcode() const {
        return m_h.arp_op;
    }

    Buffer get_src_mac() const {
        return make_buffer(m_h.arp_sha, ETHER_ADDR_LEN);
    }

    uint32_t get_src_ip() const {
        return m_h.arp_sip;
    }

    uint32_t get_dst_ip() const {
        return m_h.arp_tip;
    }

    Buffer make_request(uint32_t src_ip, uint32_t dst_ip, const uint8_t* src_mac) {
        m_h.arp_op = htons(arp_op_request);

        m_h.arp_sip = src_ip;
        m_h.arp_tip = dst_ip;

        memcpy(m_h.arp_sha, src_mac, ETHER_ADDR_LEN);
        memset(m_h.arp_tha, 0xff, ETHER_ADDR_LEN);

        return Ethernet((uint16_t)ethertype_arp, src_mac, 0,
            make_buffer((const uint8_t*)&m_h, sizeof(arp_hdr))
        ).get_packet();
    }

    Buffer make_reply(const Buffer& request, const uint8_t* src_mac) {
        m_h.arp_op = htons(arp_op_reply);
        auto arp_h = (arp_hdr*)(request.data() + sizeof(ethernet_hdr));

        // old src mac is new dst mac
        memcpy(m_h.arp_tha, arp_h->arp_sha, ETHER_ADDR_LEN);
        memcpy(m_h.arp_sha, src_mac, ETHER_ADDR_LEN);

        // src and dst ips are swapped
        m_h.arp_sip = arp_h->arp_tip;
        m_h.arp_tip = arp_h->arp_sip;

        return Ethernet(ethertype_arp, src_mac, arp_h->arp_sha,
            make_buffer((const uint8_t*)&m_h, sizeof(arp_hdr))
        ).get_packet();
    }


};
    

class IP {

private:

    ip_hdr m_h;
    Buffer data;

public:

    IP() {}

    IP(const Buffer& packet) {
        memcpy(&m_h, packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));
        data = Buffer(packet.begin() + sizeof(ethernet_hdr), packet.end());
    }

    void decrement_ttl() {
        m_h.ip_ttl--;
    }

    bool ttl_valid() const {
        return m_h.ip_ttl > 0;
    }

    static Buffer make_forwarded(const Buffer& packet, const uint8_t* src_mac, const uint8_t* dst_mac) {
        IP forwarded_ip(packet);
        forwarded_ip.decrement_ttl();
        Ethernet forwarded_ether(forwarded_ip.get_packet());
        forwarded_ether.set_src(src_mac);
        forwarded_ether.set_dst(dst_mac);
        return forwarded_ether.get_packet();
    }

    Buffer get_packet() {
        return concat_buf(make_buffer((const uint8_t*)&m_h, sizeof(ip_hdr)), data);
    };

};


class ICMP {

private:

    icmp_hdr m_h;
    Buffer data;

public:

    ICMP() {}
    ICMP(const Buffer& packet) {
        memcpy(&m_h, packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), sizeof(icmp_hdr));
        data = Buffer(packet.begin() + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr), packet.end());
    }

    Buffer echo_reply(const Buffer& packet) {
        Buffer reply = packet;
        
    }

};


} // namespace simple_router

#endif // SIMPLE_ROUTER_CORE_UTILS_HPP
