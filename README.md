# ndm_testwork
Do ARP broadcast for ip2MAC, then ICMP request. Using libpcap

# Building
Linux:
```bash
sudo apt install libpcap-dev
g++ pinger.cpp -lpcap
```

Mac:
```bash
brew install libpcap
#or
sudo port install libpcap
g++ pinger.cpp -lpcap
```

Win:
Get NPCAP [https://npcap.com/]. Make sure that wpcap.lib and Packet.lib are available in the linker path.
```bash
g++ pinger.cpp -lwpcap
```
