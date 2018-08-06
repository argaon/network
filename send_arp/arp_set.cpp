#include "arp_set.h"

void send_arp(char *snd_ip, uint8_t *snd_mac, char *trg_ip, uint8_t *trg_mac, int op, pcap_t *fp)
{
    struct send_arp_packet arph;

    memcpy(arph.ether_shost,snd_mac,ETHER_ADDR_LEN);
    arph.ether_type = htons(0x0806);

    inet_pton(AF_INET,snd_ip,&arph.sender_ip);
    inet_pton(AF_INET,trg_ip,&arph.target_ip);

    memcpy(arph.sender_mac,arph.ether_shost,ETHER_ADDR_LEN);
    memset(arph.target_mac,0x00,ETHER_ADDR_LEN);
    arph.ar_hrd = htons(0x0001);
    arph.ar_pro = htons(0x0800);
    arph.ar_hln = 0x06;
    arph.ar_pln = 0x04;
    if(op == REQUEST)
    {
        memset(arph.ether_dhost,0xFF,ETHER_ADDR_LEN);
        arph.ar_op = htons(0x0001);
    }
    else
    {
        memcpy(arph.ether_dhost,trg_mac,ETHER_ADDR_LEN);
        memcpy(arph.target_mac,trg_mac,ETHER_ADDR_LEN);
        arph.ar_op = htons(0x0002);
    }
    if(pcap_sendpacket(fp,(const u_char*)&arph,42) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
    }

}

