#include "EthernetHeader.h"

EthernetHeader::EthernetHeader(const u_char* start_header){

	ethernet_header = std::make_shared<const ETHHR> (*(reinterpret_cast<const ETHHR*> (const_cast<u_char*> (start_header))));
    

    set_mac_src_addr();
    set_mac_dst_addr() ;
	ether_type =(ntohs(ethernet_header->ether_type)==ETHERTYPE_IP)?"IP":
	(ntohs(ethernet_header->ether_type)==ETHERTYPE_PUP)?"PUP":
	(ntohs(ethernet_header->ether_type)==ETHERTYPE_ARP)?"ARP":
    (ntohs(ethernet_header->ether_type)==ETHERTYPE_IPV6)?"IP protocol version 6":
    (ntohs(ethernet_header->ether_type)==ETHERTYPE_IPX)?"IPX":
    (ntohs(ethernet_header->ether_type)==ETHERTYPE_VLAN)?"IEEE 802.1Q VLAN tagging":
    (ntohs(ethernet_header->ether_type)==ETHERTYPE_AT)?"AppleTalk protocol":"";
}

std::string EthernetHeader::get_ethernet_type() const {return ether_type;}
std::string EthernetHeader::get_dest_host() const {return ether_dst_host;}
std::string EthernetHeader::get_source_host() const {return ether_src_host;}



void EthernetHeader::set_mac_src_addr(){
    ether_src_host = "";
    for (int i=0;i<ETH_ALEN;i++){
        ether_src_host += convertIntToString((int) ethernet_header ->ether_shost[i]);
    }
}


void EthernetHeader::set_mac_dst_addr(){
	ether_dst_host = "";
    for (int i=0;i<ETH_ALEN;i++){
        ether_dst_host += convertIntToString((int) ethernet_header ->ether_dhost[i]);
    }
}

void EthernetHeader::print_mac_addr()const{
    std::cout << "Layer 2:" << std::endl; 
    std::cout << "      dst: " << ether_dst_host << std::endl;
    
    std::cout << "      src: " << ether_src_host << std::endl;
    std::cout << "      type: " << ether_type << std::endl;
    
}



std::string convertIntToString(int num){
    std::stringstream stream;
    stream << std::setfill ('0') << std::setw(2) << std::hex <<  num << std::dec;
    return stream.str();
}


