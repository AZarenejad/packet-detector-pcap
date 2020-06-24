#include "headers/UDPHeader.h"


UDPHeader::UDPHeader(const u_char* start_header)
{
	udp_header = std::make_shared<const UDPHR> (*(reinterpret_cast<const UDPHR*> (const_cast<u_char*> (start_header))));
	src_port = ntohs((udp_header.get())->source);
	dst_port = ntohs((udp_header.get())->dest);
	size = static_cast<int> (ntohs((udp_header.get())->uh_ulen));
}

void UDPHeader::print_udp_header()const
{
	std::cout << "Layer 4" << std::endl;
	std::cout << "	Src port: " << src_port << std::endl;
    std::cout << "	Dst port: " << dst_port << std::endl;
	std::cout << "	size header + data : " << size << std::endl;
}