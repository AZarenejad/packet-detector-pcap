#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "EthernetHeader.h"
#include "IPHeader.h"
#include "TCPHeader.h"
#include "UDPHeader.h"
#include "./protobuf/config.pb.h"
#include "./protobuf/config.pb.cc"
#include <fstream>
#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <fcntl.h>


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

std::string readConfigFile(std::string configFileName){
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    pcapDetector::Config config;
    int fd = open(configFileName.c_str(), O_RDONLY);
    google::protobuf::io::FileInputStream fstream(fd);
    google::protobuf::TextFormat::Parse(&fstream, &config);
    return config.filename();
}

int main(int argc , char * argv[]) {
    std::string configFileName = argv[1];
    std::string testFileName = readConfigFile(configFileName);
    std::cout << "pcap file name is: " << testFileName << std::endl;

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(testFileName.c_str(), errbuf);
    if (handle == NULL) {
        std::cout << "pcap_open_offline failed: " << errbuf << std::endl;
        return 1;
    }

    if (pcap_loop(handle, -1, packetHandler, NULL) < 0) {
      std::cout << "pcap_loop() failed: " << pcap_geterr(handle);
      return 1;
    }

    std::cout<<"Capture finished!" << std::endl;
    return 0;
}




void packetHandler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet) {
    static int count = 1; 
    std::cout << "\nPacket number "<< count << std::endl;
    count++;
    
    EthernetHeader* ethernet_header = new EthernetHeader(packet);
    IPHeader* ip_header;
    TCPHeader* tcp_header;
    UDPHeader* udp_header;

    ethernet_header->print_mac_addr();
    
    if (ethernet_header->get_ethernet_type() == "IP")
    {
      ip_header = new IPHeader(packet + sizeof(struct ether_header));
      ip_header->print_ip_addresss();
      if (ip_header->get_ip_protocol()== "TCP")
      {
        tcp_header = new TCPHeader(packet + sizeof(struct ether_header) + ip_header->get_ip_header_size());
        tcp_header->print_tcp_header();
        delete tcp_header;
      }
      else if (ip_header->get_ip_protocol()== "UDP")
      {
        udp_header = new UDPHeader(packet + sizeof(struct ether_header) + ip_header->get_ip_header_size());
        udp_header->print_udp_header();
        delete udp_header;
      }
      else
      {
        /* code */
      }
      delete ip_header;
    }
    
  
    delete ethernet_header;
  
}