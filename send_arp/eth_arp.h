#ifndef ETH_ARP_H
#define ETH_ARP_H
#pragma pack(push,1)
struct send_arp_packet
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
    uint16_t ar_hrd;          /* format of hardware address */
    uint16_t ar_pro;         /* format of protocol address */
    uint8_t  ar_hln;         /* length of hardware address */
    uint8_t  ar_pln;         /* length of protocol addres */
    uint16_t ar_op;          /* operation type op code */
    uint8_t sender_mac[ETHER_ADDR_LEN]; /*sender ethernet address*/
    uint32_t sender_ip;                 /*sender ip address*/
    uint8_t target_mac[ETHER_ADDR_LEN]; /*target ethernet address*/
    uint32_t target_ip;                 /*target ip address*/
};
#pragma pack(pop)
#endif // ETH_ARP_H
