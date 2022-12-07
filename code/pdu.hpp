#include "core/protocol.hpp"
#include "core/utils.hpp"

namespace simple_router {

Buffer make_buffer(const uint8_t* data, size_t len);
Buffer concat_buf(const Buffer& a, const Buffer& b);
    
class PDU {
protected:
    Buffer m_data;
    static const size_t min_length = 0;
public:
    PDU(const Buffer& packet) {m_data = packet;}
    Buffer data() const {return m_data;}
    virtual bool verify_length() const {return m_data.size() >= min_length;};
};

class Ethernet: public PDU {
protected:
    ethernet_hdr* eth_h;
    static const size_t min_length = sizeof(ethernet_hdr);
public:
    Ethernet(const Buffer& packet): PDU(packet) {eth_h = (ethernet_hdr*)m_data.data();}
    
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

protected:
    static const size_t min_length = sizeof(ethernet_hdr) + sizeof(arp_hdr);

    arp_hdr* arp_h;

    void set_arp_defaults() {
        arp_h = (arp_hdr*)(m_data.data() + sizeof(ethernet_hdr));
        arp_h->arp_hrd = htons(arp_hrd_ethernet);
        arp_h->arp_pro = htons(ethertype_ip);
        arp_h->arp_hln = ETHER_ADDR_LEN;
        arp_h->arp_pln = sizeof(uint32_t);
        set_eth_type(ethertype_arp);
    }


public:
    ARP(): ARP(Buffer(min_length)) {}
    ARP(const Buffer& packet): Ethernet(packet) {set_arp_defaults();}
    unsigned short get_arp_opcode() const {return ntohs(arp_h->arp_op);}
    Buffer get_arp_src_mac() const    {return make_buffer(arp_h->arp_sha, ETHER_ADDR_LEN);}
    uint32_t get_arp_src_ip() const   {return arp_h->arp_sip;}
    uint32_t get_arp_dst_ip() const   {return arp_h->arp_tip;}

    void make_arp_request(uint32_t src_ip, uint32_t dst_ip, const uint8_t* src_mac) {
        arp_h->arp_op = htons(arp_op_request);

        arp_h->arp_sip = src_ip;
        arp_h->arp_tip = dst_ip;

        memcpy(arp_h->arp_sha, src_mac, ETHER_ADDR_LEN);
        memset(arp_h->arp_tha, 0, ETHER_ADDR_LEN);

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
protected:
    ip_hdr* ip_h;
    static const size_t min_length = sizeof(ethernet_hdr) + sizeof(ip_hdr);
    void set_ttl(const uint8_t ttl) {ip_h->ip_ttl = ttl;}

    void make_ip_cksum() {
        ip_h->ip_sum = 0;
        ip_h->ip_sum = cksum(ip_h, sizeof(ip_hdr));
    }
public:
    IP(): IP(Buffer(min_length)) {}
    IP(const Buffer& packet): Ethernet(packet) {
        ip_h = (ip_hdr*)(m_data.data() + sizeof(ethernet_hdr));
    }

    bool verify_checksum() {
        uint16_t old_sum = ip_h->ip_sum;
        ip_h->ip_sum = 0;
        return cksum(ip_h, sizeof(ip_hdr)) == old_sum;
    }
    void decrement_ttl     ()       {ip_h->ip_ttl--;}
    size_t ip_data_len     () const {return m_data.size() - sizeof(ethernet_hdr);}
    uint8_t get_ip_ttl     () const {return ip_h->ip_ttl;}
    uint32_t get_ip_src_ip () const {return ip_h->ip_src;}
    uint32_t get_ip_dst_ip () const {return ip_h->ip_dst;}
    uint8_t get_ip_protocol() const {return ip_h->ip_p;}
    uint16_t get_ip_id     () const {return ntohs(ip_h->ip_id);}
    void set_ip_id(uint16_t id) {ip_h->ip_id = htons(id);}
    void set_ip_src_ip(uint32_t src) {ip_h->ip_src = src;}
    void set_ip_dst_ip(uint32_t dst) {ip_h->ip_dst = dst;}

    void make_reply(const uint32_t src_ip) {
        ip_h->ip_len = htons(m_data.size() - sizeof(ethernet_hdr));
        set_ttl(64);
        ip_h->ip_p = ip_protocol_icmp;
        set_ip_dst_ip(get_ip_src_ip());
        set_ip_src_ip(src_ip);
        make_ip_cksum();

        // swap MAC addresses

        Buffer tmp = get_eth_src();
        set_eth_src(get_eth_dst().data());
        set_eth_dst(tmp.data());
    }


    void make_forwarded(const uint8_t* src_mac) {
        make_ip_cksum();
        // swap MAC addresses
        set_eth_dst(get_eth_src().data());
        set_eth_src(src_mac);
    }


};


class ICMP: public IP {

protected:
    static const size_t min_length = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
    const size_t header_offset = sizeof(ethernet_hdr) + sizeof(ip_hdr);
    icmp_t3_hdr* icmp_h;

    void make_icmp_cksum() {
        icmp_h->icmp_sum = 0;
        icmp_h->icmp_sum = cksum(icmp_h, sizeof(icmp_t3_hdr));
    }
    void add_icmp_data() {
        size_t data_len = ip_data_len();
        m_data.resize(min_length, 0);
        if (data_len > ICMP_DATA_SIZE) {
            memmove(icmp_h->data, ip_h, ICMP_DATA_SIZE);
        } else {
            memmove(icmp_h->data, ip_h, data_len);
            memset(icmp_h->data + data_len, 0, ICMP_DATA_SIZE - data_len);
        }
    }
    void make_unreachable(uint8_t type, uint8_t code, uint32_t src_ip) {
        add_icmp_data();
        icmp_h->icmp_type = type;
        icmp_h->icmp_code = code;
        make_icmp_cksum();
        make_reply(src_ip);
    }
public:
    ICMP(): ICMP(Buffer(min_length)) {}
    ICMP(const Buffer& packet): IP(packet) {
        icmp_h = (icmp_t3_hdr*)(m_data.data() + header_offset);
    }
    uint8_t get_icmp_type() const {return icmp_h->icmp_type;}

    bool verify_checksum() {
        uint16_t old_sum = icmp_h->icmp_sum;
        icmp_h->icmp_sum = 0;
        return cksum(icmp_h, m_data.size() - header_offset) == old_sum;
    }

    void make_echo_request() {
        icmp_h->icmp_type = 8;
        icmp_h->icmp_code = 0;
        make_icmp_cksum();
    }

    void make_echo_reply(const uint8_t* src_mac) {
        icmp_h->icmp_type = 0;
        icmp_h->icmp_code = 0;
        make_icmp_cksum();
        make_reply(get_ip_dst_ip());
        set_eth_src(src_mac);
    }

    void make_time_exceeded(const uint32_t src_ip, const uint8_t* src_mac, const uint8_t* dst_mac) {
        add_icmp_data();
        icmp_h->icmp_type = 11;
        icmp_h->icmp_code = 0;
        make_icmp_cksum();
        set_ttl(64);
        make_reply(src_ip);
    }

    void make_host_unreachable(uint32_t src_ip) {make_unreachable(3, 1, src_ip);}
    void make_port_unreachable(uint32_t src_ip) {make_unreachable(3, 3, src_ip);}

};

}