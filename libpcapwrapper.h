#if defined(_WIN32) || defined(_WIN64)
	#define OS_WIN
#elif defined(__APPLE__) && defined(__MACH__)
	#define OS_MACOSX
#elif defined(__linux__)
	#define OS_LINUX
#else
	#error "Unsupported operating system"
#endif

#include <pcap.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <chrono>
#include <functional>

#ifdef OS_WIN
#include <winsock2.h>        // inet_addr, inet_ntoa
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#define close closesocket
#define getpid GetCurrentProcessId
typedef int socklen_t;
#define AF_PACKET       0x0003
#endif

#ifdef OS_LINUX
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>       // inet_addr, inet_ntoa
#endif

#ifdef OS_MACOSX
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>       // inet_addr, inet_ntoa
#include <net/if_dl.h>
#define AF_PACKET   AF_LINK
#define sll_addr    sdl_data
#define sll_family  sdl_family
#define sll_length  sdl_alen
#endif

/*
 * Some structures for cross-platrom compilation
 */


#ifndef sockaddr_ll
// minimal for cross-platrorm compilation
struct sockaddr_ll {
    uint8_t sll_family;     // address family
    uint8_t sll_addr[6];    // MAC address
};
#endif

#ifndef ether_header
struct ether_header {
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
};
#endif

#ifndef arphdr
struct arphdr {
    uint16_t ar_hrd;     // Hardware type
    uint16_t ar_pro;     // Protocol type
    uint8_t  ar_hln;     // Hardware address length
    uint8_t  ar_pln;     // Protocol address length
    uint16_t ar_op;      // Operation
};
#endif

#ifndef iphdr
struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
#error "Please fix <endian.h>"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
#endif

#define ETHERTYPE_IP   0x0800
#define ETH_PACKET_LEN 14
#define ARP_PACKET_LEN 28

/*
 * PCAP Wrapper
 */

class libpcapWrapper {

    using PacketDataExtractor = std::function<std::string(const uint8_t*, size_t)>;
    using ErrorHandler = std::function<void(const std::string &)>;

private:
    pcap_t* handle_;
    char errbuf_[PCAP_ERRBUF_SIZE];
    ErrorHandler onerror_;

public:
    std::string IF;
    std::string IP;
    std::string MAC;

public:
    libpcapWrapper(const std::string& ifname = "", ErrorHandler onError = nullptr)
        : handle_(nullptr) {

        if (!onError) {
            onerror_ = [](const std::string &msg) {
                std::cerr << msg << std::endl;
            };
        }

        if (!openInterface(ifname)) {
            onerror_("Failed to open network interface");
        }
    }

    virtual ~libpcapWrapper() {
        if (handle_) pcap_close(handle_);
    }

    std::string sendAndWait(
        const std::vector<uint8_t>& packet,
        PacketDataExtractor extractData,
        int timeout_ms = 5000,
        const std::string& bpf_filter = "") 
    {
        if (!bpf_filter.empty()) {
            struct bpf_program filterProgram;

            if (pcap_compile(handle_, &filterProgram, bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN)) {
                onerror_("Error compiling BPF filter");
                return "";
            }

            if (pcap_setfilter(handle_, &filterProgram)) {
                onerror_("Error setting BPF filter");
                pcap_freecode(&filterProgram);
                return "";
            }

            pcap_freecode(&filterProgram);
        }

        struct pcap_pkthdr* header;
        const uint8_t* data;

        if (pcap_sendpacket(handle_, packet.data(), packet.size())) {
            onerror_("Error sending packet: " + std::string(pcap_geterr(handle_)));
            return "";
        }

        auto start = std::chrono::steady_clock::now();
        auto timeout = std::chrono::milliseconds(timeout_ms);

        while (std::chrono::steady_clock::now() - start < timeout) {
            int res = pcap_next_ex(handle_, &header, &data);

            if (res == -1 || res == -2) break;
            if (res != 1) continue;

            auto result = extractData(data, header->len);
            if (!result.empty()) {
                return result;
            }
        }

        onerror_("Timeout waiting for response");
        return "";
    }

    static bool MAC2buf(const std::string &mac_str, uint8_t *mac_bytes) {
        if (mac_str.size() != 17) return false;

        for (int i = 0, j = 0; i < 6; ++i) {
            std::string byte_str = mac_str.substr(j, 2);
            char* end;
            int val = strtol(byte_str.c_str(), &end, 16);
            if (*end != '\0') return false;
            mac_bytes[i] = static_cast<uint8_t>(val);
            j += 3;
        }
        return true;
    }

private:

    bool setSuitableIF(const std::string &preferredIF = "")
    {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf_) == -1) {
            onerror_("Error finding interfaces: " + std::string(errbuf_));
            return false;
        }

        pcap_if_t* suitableDev = nullptr;

        for (pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next)
        {
            bool isLoopback = dev->flags & PCAP_IF_LOOPBACK;
            bool hasAddr = dev->addresses != nullptr;

            if (isLoopback || !hasAddr) continue;

            if (suitableDev == nullptr) {
                suitableDev = dev;
            }

            if (!preferredIF.empty() && std::string(dev->name) == preferredIF) {
                suitableDev = dev;
                break;
            }
        }

        if (!suitableDev) {
            pcap_freealldevs(alldevs);
            onerror_("No suitable network interface found");
            return false;
        }

        IF = suitableDev->name;

        bool foundMac = false, foundIp = false;

        for (pcap_addr_t *addr = suitableDev->addresses; addr != nullptr; addr = addr->next)
        {
            if (!addr->addr) continue;

            if (!foundMac && (addr->addr->sa_family == AF_PACKET || addr->addr->sa_family == AF_PACKET))
            {
                struct sockaddr_ll *sll = reinterpret_cast<struct sockaddr_ll*>(addr->addr);
                const uint8_t* mac_data = sll->sll_addr;
                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         mac_data[0], mac_data[1], mac_data[2],
                         mac_data[3], mac_data[4], mac_data[5]);
                MAC = mac_str;
                foundMac = true;
            }

            if (!foundIp && addr->addr->sa_family == AF_INET)
            {
                struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in*>(addr->addr);
                IP = inet_ntoa(sin->sin_addr);
                foundIp = true;
            }
        }

        pcap_freealldevs(alldevs);

        if (foundMac && foundIp) {
            return true;
        } else {
            onerror_("Failed to get full info (MAC/IP) for interface");
            return false;
        }
    }

    bool openInterface(const std::string& ifname = "")
    {
        setSuitableIF(ifname);

        handle_ = pcap_create(IF.c_str(), errbuf_);
        if (!handle_) {
            onerror_("Error creating pcap");
            return false;
        }
        
        auto promisc_err = pcap_set_promisc(handle_, 1);

        if (promisc_err != 0 && promisc_err != PCAP_ERROR_ACTIVATED) {
            onerror_("Error enabling promiscuous mode: " + std::to_string(promisc_err));
            return false;
        }

        if (pcap_set_timeout(handle_, 5000) != 0) {
            onerror_("Error setting pcap timeout");
            return false;
        }

        if (pcap_activate(handle_) < 0) { // skip warnings
            onerror_(std::string("Error activating pcap") + pcap_geterr(handle_));
            return false;
        }

        if (pcap_datalink(handle_) != DLT_EN10MB) { // LINKTYPE_ETHERNET
            onerror_("Unsupported link type");
            return false;
        }

        if (pcap_setdirection(handle_, PCAP_D_IN) != 0) {
            onerror_("Warning: failed to set packet direction to incoming");
        }

        if (!getInterfaceMAC(IF)) {
            onerror_("Failed to get MAC address for interface: " + IF);
            return false;
        }

        if (!getInterfaceIP(IF)) {
            onerror_("Failed to get IP address for interface: " + IF);
            return false;
        }

        return true;
    }

    bool getInterfaceMAC(const std::string& ifname)
    {
        struct ifreq ifr;
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

        if (sockfd < 0) return false;

        strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) >= 0) {
            const uint8_t* mac_data = reinterpret_cast<const uint8_t*>(ifr.ifr_hwaddr.sa_data);
            
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac_data[0], mac_data[1], mac_data[2],
                     mac_data[3], mac_data[4], mac_data[5]);

            MAC = mac_str;
            close(sockfd);
            return true;
        }

        close(sockfd);
        return false;
    }

    bool getInterfaceIP(const std::string& ifname)
    {
        struct ifreq ifr;
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

        if (sockfd < 0) return false;

        strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

        if (ioctl(sockfd, SIOCGIFADDR, &ifr) >= 0) {
            IP = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
            close(sockfd);
            return true;
        }

        close(sockfd);
        return false;
    }
};
