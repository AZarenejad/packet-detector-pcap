
#include "headers/SipHeader.h"



Sip::Sip(const u_char* start_header, int len_payload){
    for (int i=0 ;i<len_payload;i++){
        payload+= start_header[i];
    }
    std::stringstream ss(payload);
    std::string m;
    while(ss>>m){
        // std::cout << m << std::endl;
        if (m.compare("Call-ID:") == 0)
        {
            ss >> m;
            // std::cout << m << std::endl;
            call_id = m ;
        }
        else if(m.compare("From:")==0){
            ss >> m;
            // std::cout << m << std::endl;
            from = m ;
        }
        else if(m.compare("To:")==0){
            ss >> m;
            // std::cout << m << std::endl;
            to = m ;
        }
    }

 

}


std::string Sip::get_payload() const{
    return payload;
}


std::string Sip::get_call_id() const{
    return call_id;
}

std::string Sip::get_from() const{
    return from;
}

std::string Sip::get_to() const{
    return to;
}



void Sip::print_info() const{
    std::cout << "Sip Info" << std::endl;
    std::cout << "   Call-ID: " << call_id << std::endl;
    std::cout << "   From: " << from << std::endl;
    std::cout << "   To: " << to << std::endl;

}


bool Sip::packetIsSip() {
    std::stringstream ss(payload);
    if (payload.substr(0,3).compare("SIP")==0)
    {
        type = "response";
        return true;
    }
    else {
        std::string tmp = "";
        std::string tmp1 = "";
        ss >> tmp;
        ss >> tmp1;
        if (tmp1.substr(0,4).compare("sip:")==0){
            type = "request";
            return true;
        }
        return false;
    }
}