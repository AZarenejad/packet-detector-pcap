#include <pcap.h>
#include <iostream>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iomanip>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
        
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)   //??????????????????
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)      //???????????????

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


struct sniff_udp {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};






void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);




void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	static int count = 1;                 

	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;              
	const struct sniff_tcp *tcp; 
    const struct sniff_udp *udp;           
	u_char *payload;                    

	int size_ip;
	int size_tcp;
	int size_payload;

    std::cout << "\nPacket number "<< count << std::endl;
    count++;
	


	ethernet = (struct sniff_ethernet*)(packet);



    std::cout << "MAC address" << std::endl; 

    std::cout << "      dst: ";
    for (int i=0;i<ETHER_ADDR_LEN;i++){
        std::cout << std::hex << (int)(ethernet->ether_dhost)[i] << std::dec;
    }
    
    std::cout << "\n      src: ";
     for (int i=0;i < ETHER_ADDR_LEN; i++){
        std::cout << std::hex << (int)(ethernet->ether_shost)[i] << std::dec;
    }

    std::cout << "\n";



	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
        std::cout<< "Invalid Ip header length: " << size_ip << "bytes" << std::endl;
		return;
	}

    std::cout << "IP address" << std::endl; 
	std::cout << "      From: " << inet_ntoa(ip->ip_src) << std::endl;
	std::cout << "      To: " << inet_ntoa(ip->ip_dst) << std:: endl;



	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	        size_tcp = TH_OFF(tcp)*4;
	        if (size_tcp < 20) {
                std::cout << "Invalid TCP header length: "<<  size_tcp << std::endl;
		        return;
	        }
	
            std::cout << "Aplication Ports:" << std::endl;
            std::cout << "      Src port: " << ntohs(tcp->th_sport) << std::endl;
            std::cout << "      Dst port: " << ntohs(tcp->th_sport) << std::endl;
			break;

		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
            udp = (struct sniff_udp*)((packet + SIZE_ETHERNET + size_ip));
            std::cout << "Aplication Ports:" << std::endl;
            std::cout << "      Src port: " << ntohs(udp->uh_sport) << std::endl;
            std::cout << "      Dst port: " << ntohs(udp->uh_dport) << std::endl;
			return;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("Protocol: IP\n");
			return;
		default:
			printf("Protocol: unknown\n");
			return;
	}
	

	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
return;
}






int main(int argc, char const *argv[])
{

    std::string file_name = "./sample.pcap";

    char errbuff[PCAP_ERRBUF_SIZE];

    pcap_t * handle = pcap_open_offline(file_name.c_str(), errbuff);

	pcap_loop(handle, -1,  packet_handler, NULL);

	pcap_close(handle);

	printf("\nCapture complete.\n");

    return 0;
}
