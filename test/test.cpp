#include <gtest/gtest.h>

#include <fstream>
#include <memory>

#include "../headers/EthernetHeader.h"
#include "../headers/IPHeader.h"
#include "../headers/TCPHeader.h"
#include "../headers/UDPHeader.h"
#include "../headers/SipHeader.h"

TEST(pcapDetector, Ethernet)
{
    //tcp packet test from sample0.pcap (first packet) test ethernet part
    std::ifstream ifs("test_tcp.txt");
    unsigned char packet[1024];
    ifs.read((char*)( &packet[0] ),1024);
    EthernetHeader* ethernet_header = new EthernetHeader((const u_char*) packet);
    ASSERT_EQ(ethernet_header->get_dest_host(),"3af889b8aa59");
    ASSERT_EQ(ethernet_header->get_source_host(),"f0038cac3f7f");
    ASSERT_EQ(ethernet_header->get_ethernet_type(),"IP");
}

TEST(pcapDetector, Ip)
{
    //tcp packet test from sample0.pcap (first packet) test ip part
    std::ifstream ifs("test_tcp.txt");
    unsigned char packet[1024];
    ifs.read((char*)( &packet[0]), 1024);
    IPHeader* ip_header = new IPHeader((const u_char*) packet + sizeof(struct ether_header));
    ASSERT_EQ(ip_header->get_src_ip(), "192.168.43.73");
    ASSERT_EQ(ip_header->get_dst_ip(), "190.2.144.24");
    ASSERT_EQ(ip_header->get_ip_protocol(), "TCP");
    ASSERT_EQ(ip_header->get_ip_header_size(), 20);
}

TEST(pcapDetector, Tcp)
{
    //tcp packet test from sample0.pcap (first packet) test tcp part
    std::ifstream ifs("test_tcp.txt");
    unsigned char packet[1024];
    ifs.read((char*)(&packet[0]), 1024);
    IPHeader* ip_header = new IPHeader((const u_char*) packet + sizeof(struct ether_header));
    TCPHeader* tcp_header = new TCPHeader(packet + sizeof(struct ether_header) + ip_header->get_ip_header_size());
    ASSERT_EQ(tcp_header->get_src_port(), 42466);
    ASSERT_EQ(tcp_header->get_des_port(), 443);
}

TEST(pcapDetector, Udp)
{
    //udp packet test from sample0.pcap (first packet) test udp part
    std::ifstream ifs("test_udp.txt");
    unsigned char packet[1024];
    ifs.read((char*)( &packet[0]), 1024);
    IPHeader* ip_header = new IPHeader((const u_char*) packet + sizeof(struct ether_header));
    UDPHeader* udp_header = new UDPHeader(packet + sizeof(struct ether_header) + ip_header->get_ip_header_size());
    ASSERT_EQ(ip_header->get_src_ip(), "216.58.208.238");
    ASSERT_EQ(ip_header->get_dst_ip(), "192.168.43.73");
    ASSERT_EQ(udp_header->get_src_port(), 443);
    ASSERT_EQ(udp_header->get_dst_port(), 59229);
}

TEST(pcapDetector, SipDetect)
{
    //the first two tests is simple tcp and udp but not sip in application layer
    std::ifstream ifs("test_udp.txt");
    unsigned char packet[1024];
    ifs.read((char*)( &packet[0]), 1024);
    IPHeader* ip_header = new IPHeader((const u_char*) packet + sizeof(struct ether_header));
    UDPHeader* udp_header = new UDPHeader(packet + sizeof(struct ether_header) + ip_header->get_ip_header_size());
    Sip* sip_header = new Sip(packet + sizeof(struct ether_header) + ip_header->get_ip_header_size() + 8 ,
        udp_header->get_size()-8);
    ASSERT_EQ(sip_header->packetIsSip(), false);
}

TEST(pcapDetector, SipOutput)
{
    // test sip with sample2.pcap packet 20
    std::ifstream ifs("test_sip.txt");
    unsigned char packet[1024];
    ifs.read((char*)( &packet[0]), 1024);
    IPHeader* ip_header = new IPHeader((const u_char*) packet + sizeof(struct ether_header));
    UDPHeader* udp_header = new UDPHeader(packet + sizeof(struct ether_header) + ip_header->get_ip_header_size());
    Sip* sip_header = new Sip(packet + sizeof(struct ether_header) + ip_header->get_ip_header_size() + 8 ,
        udp_header->get_size()-8);
    ASSERT_EQ(sip_header->packetIsSip(), true);
    ASSERT_EQ(sip_header->get_call_id(), "578222729-4665d775@578222732-4665d772");
    ASSERT_EQ(sip_header->get_from(), "<sip:voi18063@sip.cybercity.dk>;tag=903df0a");
    ASSERT_EQ(sip_header->get_to(), "<sip:voi18063@sip.cybercity.dk>;tag=00-04092-1701af62-120c67172");
}

int main(int argc, char* argv[])
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}