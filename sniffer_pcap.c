
#include "pcap.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s  <capture-file>\n", argv[0]);
        exit(-1);
    }

    // Open our capture file, overwrite if it already exists.
    FILE *fp = fopen(argv[1], "wb");
    if (!fp)
    {
        fprintf(stderr, "fopen(%s) failed: %d\n", argv[2], errno);
        exit(-1);
    }

    setbuf(fp, NULL);

    // Create a PCAP  GLobal file header.
    struct pcap_file_header hdr;
    hdr.magic = 0xa1b2c3d4;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.snaplen = BUFFER_SIZE_PKT;
    hdr.sigfigs = 0;
    hdr.linktype = DLT_EN10MB;

    // Write the PCAP file header to our capture file.
    if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1)
    {
        fprintf(stderr, "fwrite(pcap_file_header) failed: %u", errno);
        exit(-1);
    }
    //Creating RAW socket
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }

    unsigned char buffer[BUFFER_SIZE_HDR + BUFFER_SIZE_PKT];
    memset(buffer, 0, sizeof(buffer));
    buffer[BUFFER_OFFSET_ETH + 12] = 0x08;
    struct pcap_sf_pkthdr *pkt = (struct pcap_sf_pkthdr *)buffer;
    struct timeval time;

    // Read packets forever.
    while (1)
    {
        // Read the next packet, blocking forever.
        int rc = recv(sock_raw, (char *)buffer + BUFFER_OFFSET_ETH, BUFFER_SIZE_PKT, 0);
        if (rc < 0)
        {
            fprintf(stderr, "recv() failed: %s", strerror(errno));
            exit(-1);
        }
        if (rc == 0)
            break;

        // Calculate a high resolution timestamp for this packet.
        // Set out PCAP packet header fields.
        gettimeofday(&time, NULL);
        pkt->ts.tv_sec = (int32_t)time.tv_sec;
        pkt->ts.tv_usec = (int32_t)time.tv_usec;
        pkt->caplen = rc + BUFFER_SIZE_ETH;
        pkt->len = rc + BUFFER_SIZE_ETH;

        // Output our packet data and header in a single write.
        if (fwrite(buffer, rc + BUFFER_SIZE_ETH + BUFFER_SIZE_HDR, 1, fp) != 1)
        {
            fprintf(stderr, "fwrite(buffer) failed: %d", errno);
            exit(-1);
        }
    }

    // Our socket and file will be closed automatically.
    return 0;
}
