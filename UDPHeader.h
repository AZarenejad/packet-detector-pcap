#ifndef UDP_HEADER_H
#define UDP_HEADER_H

#include <netinet/udp.h>
#include <iostream>
#include <memory>
#include <arpa/inet.h>

typedef struct udphdr UDPHR; 

class UDPHeader
{
private:
	std::shared_ptr<const UDPHR> udp_header;
    u_int src_port;
	u_int dst_port;
    int size;
public:
    UDPHeader(const u_char* start_header);
    inline u_int get_src_port(){return src_port;}
	inline u_int get_dst_port(){return dst_port;}
    void print_udp_header()const;
    int get_size(){return size;}


	
};

#endif