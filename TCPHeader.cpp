#include "TCPHeader.h"

TCPHeader::TCPHeader(const u_char* start_header)
{
	tcp_header = std::make_shared<struct tcphdr>(*(reinterpret_cast<struct tcphdr*>(const_cast<u_char*>(start_header))));

	src_port = ntohs((tcp_header.get())->source);
	dst_port = ntohs((tcp_header.get())->dest);
	size = static_cast<int>(tcp_header->doff) * 4;
}


void TCPHeader::print_tcp_header()const{
	std::cout << "Layer 4" << std::endl;
	std::cout << "	Src port: " << src_port << std::endl;
    std::cout << "	Dst port: " << dst_port << std::endl;
	std::cout << "	size header: " << size << std::endl;
}