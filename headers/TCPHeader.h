#ifndef TCP_HEADER_H
#define TCP_HEADER_H

#include <netinet/tcp.h>
#include <iostream>
#include <memory>
#include <arpa/inet.h>

typedef struct tcphdr TCPHR;

class TCPHeader
{
private:
	std::shared_ptr<const TCPHR> tcp_header;
    u_int src_port;
	u_int dst_port;
    int size;

public:
    TCPHeader(const u_char* start_header);
    inline u_int get_src_port(){return src_port;}
	inline u_int get_des_port(){return dst_port;}
    void print_tcp_header() const;

};

#endif
