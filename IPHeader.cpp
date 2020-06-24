#include "headers/IPHeader.h"

IPHeader::IPHeader(const u_char* start_header)
{
	ip_header = std::make_shared<const IP> (*(reinterpret_cast<const IP*> (const_cast<u_char*> (start_header))));
	inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    ip_protocol = (ip_header->ip_p == IPPROTO_TCP)?"TCP":
    			(ip_header->ip_p == IPPROTO_IP)?"IP":
    			(ip_header->ip_p == IPPROTO_UDP)?"UDP":
				(ip_header->ip_p == IPPROTO_ICMP)?"ICMP":"";
    size = static_cast<int>(ip_header->ip_hl) * 4;
}	

void IPHeader::print_ip_addresss()
{
	std::cout << "Layer 3" << std::endl; 
	std::cout << "	From: " << src_ip << std::endl;
	std::cout << "	To: " << dst_ip << std:: endl;
	if (size < 20) 
	{
        std::cout<< "	Invalid Ip header length: " << size << "bytes" << std::endl;
		return;
	}
	std::cout << "	size header: " << size << std::endl;
	std::cout << "	protocol: " << ip_protocol << std::endl;
}