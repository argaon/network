#include <pcap.h>
#include <libnet.h>
#include "arp_set.h"

void get_target_mac(uint8_t *output_target_mac,char *target_ip,pcap_t *fp){
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    struct send_arp_packet *g_arph;
    int res;

    uint16_t etype;
    uint32_t u32input_ip;
    uint32_t u32target_ip;

    inet_pton(AF_INET,target_ip,&u32input_ip);

    while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=0)
    {
        if(res== 0)continue;
        g_arph = (struct send_arp_packet*)pkt_data;
        etype = ntohs(g_arph->ether_type);
        if(etype == ETHERTYPE_ARP)
        {
            u32target_ip = g_arph->sender_ip;
            if(u32input_ip == u32target_ip)
            {
                memcpy(output_target_mac,g_arph->sender_mac,6);
                break;
            }
        }
    }
}
