#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>
#include <memory>
#include <iostream>

typedef struct ip IP;

class IPHeader
{
private:
	std::shared_ptr<const IP> ip_header;
	char src_ip [INET_ADDRSTRLEN];
	char dst_ip [INET_ADDRSTRLEN];
	std::string ip_protocol;
	int size;
public:
	IPHeader(const u_char* start_header);
	inline std::string get_src_ip(){return std::string(src_ip);}
	inline std::string get_dst_ip(){return std::string(dst_ip);}
	inline std::string get_ip_protocol(){return ip_protocol;}
	inline int get_ip_header_size(){return size;}
	void print_ip_addresss();
};

#endif