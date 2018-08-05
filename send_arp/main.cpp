#include <iostream>
#include <libnet.h>
#include "eth_arp.h"
#include "get_my_addr.h"

using namespace std;

int main(int argc,char *argv[])
{
    struct libnet_ethernet_hdr *eh;
    struct send_arp_packet *arp;
    char *dev = argv[1];
    char atk_ip[INET_ADDRSTRLEN];
    uint8_t atk_mac[6];

    get_my_addr(dev,atk_ip,atk_mac);
    for(int i=0;i<6;i++)
        printf("%02x ",atk_mac[i]);
    return 0;
}
