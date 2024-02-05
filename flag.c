#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    printf("Packet Captured:\n");

    // Assuming Ethernet + IP + TCP headers
    struct iphdr *ip_header = (struct iphdr *)(packet + 14);  // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ihl << 2));  // Skip Ethernet + IP headers

    // Print TCP flag codes
    printf("TCP Flags: ");
    printf("FIN: %d, SYN: %d, RST: %d, PSH: %d, ACK: %d, URG: %d\n",
           tcp_header->fin, tcp_header->syn, tcp_header->rst,
           tcp_header->psh, tcp_header->ack, tcp_header->urg);

    // Print each byte of the packet
    for (int i = 0; i < pkthdr->len; i++) {
        printf("%02X ", packet[i]);

        // Print a newline after every 16 bytes for better readability
        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    printf("\n\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open a live capture session
    handle = pcap_open_live("enp2s0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // Set a filter to capture only TCP packets
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the session
    pcap_close(handle);

    return 0;
}
