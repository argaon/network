#include <stdio.h>
#include <libnet.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string>
#include <regex>
#include <iostream>

/* returns packet id */

using namespace std;

int ncbs = 0;
char *bs;

int find_block_site(unsigned char* buf, int size) {
    struct libnet_ipv4_hdr *iph;
    struct libnet_tcp_hdr *tcph;
    regex re("Host: ([^\r]*)");
    string sbuf(reinterpret_cast<char const*>(buf), size);
    smatch m;

    int jtotd;      //'j'ump 'to' 't'cp 'd'ata pointer
    iph = (struct libnet_ipv4_hdr*)buf;
    if(iph->ip_p == IPPROTO_TCP)
    {
        buf += iph->ip_hl*4;
        tcph = (struct libnet_tcp_hdr*)buf;
        jtotd = (tcph->th_off *4);
        buf += jtotd;     //jump to tcp data
        size -= jtotd;      //pkt length - jump size
        if(size > 0)
        {
            printf("Have TCP DATA !\n");
            if((regex_search(sbuf,m,re)))
            {
                cout<<m[0]<<endl;
                if (m.str(1).compare(bs) == 0)
                {
                cout<<"Catch block site!"<<endl;
                return 1;
                }
            }
        }
        else
            printf("Have no TCP data!\n");
    }
    return 0;
}

//static u_int32_t print_pkt (struct nfq_data *tb,struct nfq_filter *nfqf)
static u_int32_t print_pkt (struct nfq_data *tb)
{

    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;

    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);

    if (ph) {
        id = ntohl(ph->packet_id);
    }
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {
        ncbs = find_block_site(data,ret);
        //nfqf->nfqnCbs = find_block_site(data,ret);
        //printf("Test Return value : %d\n",nfqf->nfqnCbs);
    }
    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)    //void *data
{
    (void)nfmsg;
    (void)data;

    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");

    return nfq_set_verdict(qh, id, (ncbs==1)?NF_DROP:NF_ACCEPT, 0, NULL);
}

int main(int argc, char *argv[])
{
    if(argc <3)
    {
        printf("Need more arguement!\n");
        printf("EX : 0 'block_stie'\n");
        exit(1);
    }

    bs = argv[2];

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    (void)nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }
    printf("binding this socket to queue '0'\n");
    //qh = nfq_create_queue(h,  0, &cb, &aaa);
    qh = nfq_create_queue(h, 0, &cb,0);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }
    printf("unbinding"
           " from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
