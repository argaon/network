#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  struct libnet_ethernet_hdr *eh;
  struct libnet_ipv4_hdr *iph;
  struct libnet_tcp_hdr *tcph;
  while (true)
  {
    struct pcap_pkthdr *header;
    const u_char *packet;
    uint32_t pkt_len = header->len;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    eh = (struct libnet_ethernet_hdr*)packet;
    uint8_t *mac = eh->ether_dhost;

    printf("Ethernet Header\n");
    printf("Dst Mac : ");
    for(int i=0;i<6;i++)
        printf("%02x ",(*mac++));
    printf("\nSrc Mac : ");
    mac = eh->ether_shost;
    for(int i=0;i<6;i++)
        printf("%02x ",(*mac++));
    printf("\n");
    uint16_t ether_type = ntohs(eh->ether_type);
    if(ether_type == ETHERTYPE_IP)
    {
        packet += sizeof(struct libnet_ethernet_hdr);
        pkt_len -= sizeof(struct libnet_ethernet_hdr);
        iph = (struct libnet_ipv4_hdr*)packet;
        printf("IP Header\n");
        char cip[20];
        inet_ntop(AF_INET,&iph->ip_src,cip,sizeof(cip));
        printf("Src Address : %s\n", cip);
        inet_ntop(AF_INET,&iph->ip_dst,cip,sizeof(cip));
        printf("Dst Address : %s\n", cip);
        if (iph->ip_p == IPPROTO_TCP)
        {
            packet += iph->ip_hl*4;
            pkt_len -= iph->ip_hl*4;
            tcph = (struct libnet_tcp_hdr*)packet;
            printf("TCP Header\n");
            printf("Src Port : %d\n" , ntohs(tcph->th_sport));
            printf("Dst Port : %d\n" , ntohs(tcph->th_dport));
            packet += tcph->th_off*4;   //header Length(bin 1000(8) * 4 = 32)
            pkt_len -= tcph->th_off*4;
            if (pkt_len > 0 )
            {
                printf("TCP Data\n");
                for(int i=0;i<16;i++)
                    printf("%02x ", packet[i]);
                printf("\n");
            }
        }
    }
  }
  pcap_close(handle);
  return 0;
}
