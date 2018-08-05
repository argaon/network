#include <ifaddrs.h>
#include <libnet.h>
void get_my_addr(const char*ifname,char* outputmyip,uint8_t*outputmymac)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0)
        perror("socket fail");
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl fail");
    memcpy(outputmymac,ifr.ifr_hwaddr.sa_data,6);

    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;

    getifaddrs(&ifAddrStruct);
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr)
        {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET)
        { // check it is IP4
            if(strcmp(ifa->ifa_name,ifname)==0)
            {
                tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, tmpAddrPtr, outputmyip, INET_ADDRSTRLEN);
            }
        }
    }
}
