#ifndef SIP_HEADER_H
#define SIP_HEADER_H

#include <sstream>
#include <iostream>
#include <string>


typedef struct osip_message SIPHDR;


class Sip 
{
private:
    std::string payload;
    std::string call_id;
    std::string from;
    std::string to ;
    std::string type;

public:
    Sip(const u_char* start_header, int len_payload);
    std::string get_payload() const;
    std::string get_call_id() const;
    std::string get_from() const;
    std::string get_to() const;
    void print_info() const;
    bool packetIsSip();

};

#endif