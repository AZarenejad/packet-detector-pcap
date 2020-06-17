#ifndef ETHERNET_HEADER_H
#define ETHERNET_HEADER_H

#include <string>
#include <memory>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <sstream> 
#include <iomanip> 

typedef struct ether_header ETHHR;

class EthernetHeader
{
private:
	std::shared_ptr<const ETHHR> ethernet_header;
	std::string ether_dst_host;
	std::string ether_src_host;
	std::string ether_type;

public:
	EthernetHeader(const u_char* start_header);
	std::string get_ethernet_type() const;
	std::string get_dest_host() const;
	std::string get_source_host() const;
	void set_mac_src_addr();
	void set_mac_dst_addr();
	void print_mac_addr() const;
	

	
};

std::string convertIntToString(int num);

#endif