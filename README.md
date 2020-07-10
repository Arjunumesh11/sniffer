## INTRODUCTION

Network sniffers take snapshot copies of the data flowing over a network without redirecting or altering it. Some sniffers work only with TCP/IP packets, but the more sophisticated tools work with many other net

### HOW NETWORK SNIFFING WORK
A packet sniffer connected to any network intercepts all data flowing over that network.
On a local area network (LAN), computers typically communicate directly with other computers or devices on the network. Anything connected to that network is exposed to all of that traffic. Computers are programmed to ignore all network traffic not intended for it.Network sniffing software opens up to all traffic by opening up the computer's network interface card (NIC) to listen to that traffic. The software reads that data and performs analysis or data extraction on it.

### NETWORK SNIFFING USING C
Network packets and packet sniffers
When an application sends data into the network, it is processed by various network layers. Before sending data, it is wrapped in various headers of the network layer. The wrapped form of data, which contains all the information like the source and destination address, is called a network packet. According to Ethernet protocols, there are various types of network packets like Internet Protocol packets, Xerox PUP packets, Ethernet Loopback packets, etc.


### RAW SOCKET 
Programming using TCP or UDP implies that only the application protocol header and data are provided by the application.The headers of IP , TCP or UDP protocols are automatically created by the O.S, using information provided by the application ( IP address, port numbers and protocol family) .  The O.S. uses default values to fields such as TTL. It is up to the O.S. to compute the checksum, sockets like stream sockets and datagram sockets receive data from the transport layer that contains no headers but only the payload. This means that there is no information about the source IP address and MAC address. If applications running on the same machine or on different machines are communicating, then they are only exchanging data.when present.Raw sockets programming, on the other hand, allows headers of lower level protocols to be constructed by the application.
#### Opening a RAW Socket
```
int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
```
As explained above raw socket can capture every packets
ETH_P_ALL specifies to capture all,if u want only IP packet u can use ETH_P_IP

#### Reception of the network packet
     // Read the next packet, blocking forever.
       int rc = recv(sock_raw, (char *)buffer + BUFFER_OFFSET_ETH,    BUFFER_SIZE_PKT, 0);
       if (rc < 0)
       {
           fprintf(stderr, "recv() failed: %s", strerror(errno));
           exit(-1);
       }
      // End of file for some strange reason, so stop reading packets.
       if (rc == 0)
           break;

Here BUFFER_SIZE_PKT specifies the size of packer 
>#define BUFFER_SIZE_PKT ((256 * 256) - 1)


### STORING DATA in trace FILE (pcap)
Pcap file format


The first part of the file is the global header, which is inserted only once in the file, at the start. The global header has a fixed size of 24 bytes.
#### GLOBAL HEADER
```
//pcap Global header
struct pcap_file_header
{
   uint32_t magic;         //used to detect the file format itself and the byte ordering.
   uint16_t version_major; //version number
   uint16_t version_minor;
   int32_t thiszone; //GMT timezone offset
   uint32_t sigfigs;
   uint32_t snaplen;  //"snapshot length" for the capture (typically 65535 or even more, but might be limited by the user)
   uint32_t linktype; //link-layer header type, specifying the type of headers at the beginning of the packet.
};
```

>magic_number: used to detect the file format itself and the byte ordering.
version_major, version_minor: the version number of this file format.
thiszone: the correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps.
sigfigs: In theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
snaplen: the "snapshot length" for the capture (typically 65535 or even more, but might be limited by the user), see: incl_len vs. orig_len below
network: link-layer header type, specifying the type of headers at the beginning of the packet.
### PACKET HEADER
```
//pcap packet header
struct pcap_sf_pkthdr
{
   struct pcap_timeval ts; //he date and time when this packet was captured.
   uint32_t caplen;        //the number of bytes of packet data actually captured and saved in the file
   uint32_t len;           //the length of the packet as it appeared on the network when it was captured.
};

//time header
struct pcap_timeval
{
   int32_t tv_sec;
   int32_t tv_usec;
};
```
ts_sec: the date and time when this packet was captured.
ts_usec: in regular pcap files, the microseconds when this packet was captured.
incl_len: the number of bytes of packet data actually captured and saved in the file.
orig_len: the length of the packet as it appeared on the network when it was captured.

### Creating Header
#### Global header
```
struct pcap_file_header hdr;
   hdr.magic = 0xa1b2c3d4;
   hdr.version_major = PCAP_VERSION_MAJOR;
   hdr.version_minor = PCAP_VERSION_MINOR;
   hdr.thiszone = 0;
   hdr.snaplen = BUFFER_SIZE_PKT;
   hdr.sigfigs = 0;
   hdr.linktype = DLT_EN10MB;
```
#### Packet header for each packet in the capture loop
```
   gettimeofday(&time, NULL);
       pkt->ts.tv_sec = (int32_t)time.tv_sec;
       pkt->ts.tv_usec = (int32_t)time.tv_usec;
       pkt->caplen = rc + BUFFER_SIZE_ETH;
       pkt->len = rc + BUFFER_SIZE_ETH;
```
Gettimeofday return high precision time
