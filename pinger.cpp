#include "libpcapwrapper.h"

struct icmp {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_cksum;
    union {
        uint16_t id_seq[2]; // ICMP_ECHO / ICMP_ECHOREPLY
        uint32_t gateway;
        struct {
            uint16_t __pad;
            uint16_t mtu;
        } frag;
    } icmp_un;
};

#define ICMP_ECHO     8
#define ICMP_ECHOREPLY 0
#define icmp_id     icmp_un.id_seq[0]
#define icmp_seq    icmp_un.id_seq[1]

/*
 * ARP part - broadcast for MAC
 */

std::vector<uint8_t> buildARPPacket(
    const std::string& target_ip,
    const std::string& src_ip,
    const std::string& src_mac
) {
    std::vector<uint8_t> arp_packet(ETH_PACKET_LEN + ARP_PACKET_LEN, 0);

    // Ethernet header
    std::fill(arp_packet.begin(), arp_packet.begin() + 6, 0xFF); // FF:FF:FF:FF:FF:FF (Broadcast)
    libpcapWrapper::MAC2buf(src_mac, arp_packet.data() + 6); // Source MAC
    arp_packet[12] = 0x08; arp_packet[13] = 0x06; // Ethertype (ARP)

    // ARP header
    arp_packet[14] = 0x00; arp_packet[15] = 0x01; // Hardware type: Ethernet (1)
    arp_packet[16] = 0x08; arp_packet[17] = 0x00; // Protocol type: IPv4 (0x0800)
    arp_packet[18] = 6;                          // Hardware address length
    arp_packet[19] = 4;                          // Protocol address length
    arp_packet[20] = 0x00; arp_packet[21] = 0x01; // Operation: ARP Request

    // Source MAC
    libpcapWrapper::MAC2buf(src_mac, arp_packet.data() + 22);

    // Source IP
    in_addr_t src_ip_in = inet_addr(src_ip.c_str());
    memcpy(arp_packet.data() + 28, &src_ip_in, 4);

    // Target MAC (zero)
    std::fill(arp_packet.begin() + 32, arp_packet.begin() + 38, 0);

    // Target IP
    in_addr_t target_ip_in = inet_addr(target_ip.c_str());
    memcpy(arp_packet.data() + 38, &target_ip_in, 4);

    return arp_packet;
}

std::string extractARPReply(const uint8_t* data, size_t len) {
    if (len < 42 || data[12] != 0x08 || data[13] != 0x06) return "";
    if (data[20] != 0x00 || data[21] != 0x02) return "";

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             data[6], data[7], data[8],
             data[9], data[10], data[11]);

    return std::string(mac_str);
}

/*
 * ICMP part - ping
 */

uint16_t checksum(void* data, size_t len)
{
    uint32_t sum = 0;
    uint16_t* arr = (uint16_t*)data;

    while (len > 1) {
        sum += *arr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(uint8_t*)arr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

std::vector<uint8_t> buildICMPPacket(
    const std::string& dst_ip_str,
    uint16_t pid,
    uint16_t seq,
    const std::string& interface_ip,
    const std::string& interface_mac,
    const std::string& dst_mac)
{
    constexpr size_t PAYLOAD_SIZE = 56;

    std::vector<uint8_t> packet(sizeof(ether_header) + sizeof(iphdr) + sizeof(icmp) + PAYLOAD_SIZE);

    auto* eth = reinterpret_cast<ether_header*>(packet.data());
    auto* ip_hdr = reinterpret_cast<iphdr*>(packet.data() + sizeof(ether_header));
    auto* icmp_hdr = reinterpret_cast<icmp*>(packet.data() + sizeof(ether_header) + sizeof(iphdr));

    // Ethernet header
    libpcapWrapper::MAC2buf(interface_mac, eth->ether_shost); // src MAC
    libpcapWrapper::MAC2buf(dst_mac, eth->ether_dhost);       // dst MAC
    eth->ether_type = htons(ETHERTYPE_IP);

    // IP header
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(sizeof(iphdr) + sizeof(icmp) + PAYLOAD_SIZE);
    ip_hdr->id = htons(45535);
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 255;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->check = 0;
    ip_hdr->saddr = inet_addr(interface_ip.c_str());
    ip_hdr->daddr = inet_addr(dst_ip_str.c_str());

    ip_hdr->check = checksum(ip_hdr, sizeof(iphdr));

    // ICMP header
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_id = htons(pid);
    icmp_hdr->icmp_seq = htons(seq);

    // fill payload
    uint8_t* payload = packet.data() + sizeof(ether_header) + sizeof(iphdr) + sizeof(icmp);
    memset(payload, 0x41, PAYLOAD_SIZE); // 'A' as payload filler

    icmp_hdr->icmp_cksum = checksum(icmp_hdr, sizeof(icmp) + PAYLOAD_SIZE);

    return packet;
}

std::string extractICMPReply(
    const uint8_t* data, size_t len,
    uint16_t expected_pid, uint16_t expected_seq)
{
    if (len < sizeof(ether_header)) return "";

    const ether_header* eth_hdr = reinterpret_cast<const ether_header*>(data);
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return "";

    if (len < sizeof(ether_header) + sizeof(iphdr)) return "";

    const iphdr* ip_hdr = reinterpret_cast<const iphdr*>(data + sizeof(ether_header));
    if (ip_hdr->protocol != IPPROTO_ICMP) return "";

    size_t ip_header_len = ip_hdr->ihl * 4;
    if (len < sizeof(ether_header) + ip_header_len + sizeof(icmp)) return "";

    const icmp* icmp_hdr = reinterpret_cast<const icmp*>(data + sizeof(ether_header) + ip_header_len);

    if (icmp_hdr->icmp_type == ICMP_ECHOREPLY &&
        icmp_hdr->icmp_id == htons(expected_pid) &&
        icmp_hdr->icmp_seq == htons(expected_seq))
    {
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->saddr), src_ip, INET_ADDRSTRLEN);
        return std::string(src_ip);
    }

    return "";
}

/*
 * main
 */

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: sudo " << argv[0] << " <IP addr>" << std::endl;
        return 1;
    }

    const std::string target_ip = argv[1];

#ifdef OS_WIN
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    libpcapWrapper pcap;

    // step 1: get destination MAC

    auto arpPacket = buildARPPacket(target_ip, pcap.IP, pcap.MAC);

    std::string dst_mac = pcap.sendAndWait(arpPacket, extractARPReply, 5000, "arp");

    if (dst_mac.empty()) {
        std::cerr << "arp request failed" << std::endl;
        return 1;
    }

    // step 2: do ping

    uint16_t pid = getpid();
    uint16_t seq = static_cast<uint16_t>(rand());

    auto icmpPacket = buildICMPPacket(target_ip, pid, seq, pcap.IP, pcap.MAC, dst_mac);

    std::string result = pcap.sendAndWait(icmpPacket,
        [&](const uint8_t* data, size_t len) -> std::string {
            return extractICMPReply(data, len, pid, seq);
        },
        5000, "icmp"
    );

    if (!result.empty()) {
        std::cout << dst_mac << std::endl;
    } else {
        std::cerr << "Ping failed or no valid reply received." << std::endl;
        return 1;
    }

#ifdef OS_WIN
    WSACleanup();
#endif

    return 0;
}
