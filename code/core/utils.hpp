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


class Layer {
protected:
    Buffer m_data;
    size_t min_length = 0;
public:
    Layer(const Buffer& packet) {m_data = packet;}
    Buffer data() const {return m_data;}
    virtual bool verify_length() const {return m_data.size() >= min_length;};
};

class Ethernet: public Layer {
private:
    ethernet_hdr* eth_h;
public:
    Ethernet(const Buffer& packet): Layer(packet) {
        eth_h = (ethernet_hdr*)m_data.data();
        min_length += sizeof(ethernet_hdr);        
    }
    
    uint16_t get_eth_type() const      {return ntohs(eth_h->ether_type);}
    Buffer get_eth_src() const         {return make_buffer(eth_h->ether_shost, ETHER_ADDR_LEN);}
    Buffer get_eth_dst() const         {return make_buffer(eth_h->ether_dhost, ETHER_ADDR_LEN);}
    void set_eth_type(uint16_t type)   {eth_h->ether_type = ntohs(type);}

    void set_eth_src(const uint8_t* src) {
        if (src) {
            memcpy(eth_h->ether_shost, src, ETHER_ADDR_LEN);
        }
    }

    void set_eth_dst(const uint8_t* dst) {
        // set dst to 0 for broadcast
        if (dst) {
            memcpy(eth_h->ether_dhost, dst, ETHER_ADDR_LEN);
        } else {
            memset(eth_h->ether_dhost, 0xff, ETHER_ADDR_LEN);
        }
    }
};

class ARP: public Ethernet {
private:
    arp_hdr* arp_h;
    void set_arp_defaults() {
        arp_h->arp_hrd = htons(arp_hrd_ethernet);
        arp_h->arp_pro = htons(ethertype_ip);
        arp_h->arp_hln = ETHER_ADDR_LEN;
        arp_h->arp_pln = sizeof(uint32_t);
        set_eth_type(ethertype_arp);
    }
public:
    ARP(const Buffer& packet): Ethernet(packet) {
        arp_h = (arp_hdr*)(m_data.data() + sizeof(ethernet_hdr));
        min_length += sizeof(ethernet_hdr);
        set_arp_defaults();
    }
    unsigned short get_arp_opcode() const {return ntohs(arp_h->arp_op);}
    Buffer get_arp_src_mac() const    {return make_buffer(arp_h->arp_sha, ETHER_ADDR_LEN);}
    uint32_t get_arp_src_ip() const   {return arp_h->arp_sip;}
    uint32_t get_arp_dst_ip() const   {return arp_h->arp_tip;}

    void make_arp_request(uint32_t src_ip, uint32_t dst_ip, const uint8_t* src_mac) {
        arp_h->arp_op = htons(arp_op_request);

        arp_h->arp_sip = src_ip;
        arp_h->arp_tip = dst_ip;

        memcpy(arp_h->arp_sha, src_mac, ETHER_ADDR_LEN);
        memset(arp_h->arp_tha, 0xff, ETHER_ADDR_LEN);

        set_eth_src(src_mac);
        set_eth_dst(0);
    }
    void make_arp_reply(const uint8_t* src_mac) {
        arp_h->arp_op = htons(arp_op_reply);

        // old src mac is new dst mac
        memcpy(arp_h->arp_tha, arp_h->arp_sha, ETHER_ADDR_LEN);
        memcpy(arp_h->arp_sha, src_mac, ETHER_ADDR_LEN);

        // src and dst ips are swapped
        uint32_t tmp = arp_h->arp_sip;
        arp_h->arp_sip = arp_h->arp_tip;
        arp_h->arp_tip = tmp;

        set_eth_src(src_mac);
        set_eth_dst(arp_h->arp_tha);

    }

};
    

class IP: public Ethernet {
private:
    ip_hdr* ip_h;
public:

    IP(const Buffer& packet): Ethernet(packet) {
        ip_h = (ip_hdr*)(m_data.data() + sizeof(ethernet_hdr));
        min_length += sizeof(ip_hdr);
    }

    bool verify_checksum() {
        uint16_t old_sum = ip_h->ip_sum;
        ip_h->ip_sum = 0;
        return cksum(ip_h, sizeof(ip_hdr)) == old_sum;
    }

    uint8_t get_ip_ttl     () const {return ip_h->ip_ttl;}
    uint32_t get_ip_src_ip () const {return ip_h->ip_src;}
    uint32_t get_ip_dst_ip () const {return ip_h->ip_dst;}
    uint8_t get_ip_protocol() const {return ip_h->ip_p;}
    void set_ip_src_ip(uint32_t src) {ip_h->ip_src = src;}
    void set_ip_dst_ip(uint32_t dst) {ip_h->ip_dst = dst;}


    void make_forwarded() {
        ip_h->ip_ttl--;
        ip_h->ip_sum = 0;
        ip_h->ip_sum = cksum(ip_h, sizeof(ip_hdr));
    }


};


class ICMP: IP {

private:
    const size_t header_offset = sizeof(ethernet_hdr) + sizeof(ip_hdr);
    icmp_hdr* icmp_h;

    void make_cksum() {
        icmp_h->icmp_sum = 0;
        icmp_h->icmp_sum = cksum(icmp_h, m_data.size() - header_offset);
    }
public:

    ICMP(const Buffer& packet): IP(packet) {
        icmp_h = (icmp_hdr*)(m_data.data() + header_offset);
        min_length += sizeof(icmp_hdr);
    }

    void make_echo_request() {
        icmp_h->icmp_type = 8;
        icmp_h->icmp_code = 0;
        make_cksum();
    }

    void make_echo_reply(const uint8_t* src_mac, const uint8_t* dst_mac) {
        icmp_h->icmp_type = 0;
        icmp_h->icmp_code = 0;
        make_cksum();
        uint32_t tmp = get_ip_src_ip();
        set_ip_src_ip(get_ip_dst_ip());
        set_ip_dst_ip(tmp);
    }

};


} // namespace simple_router

#endif // SIMPLE_ROUTER_CORE_UTILS_HPP
