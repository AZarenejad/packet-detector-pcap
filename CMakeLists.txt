cmake_minimum_required(VERSION "3.10.2")


set(CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS} -std=c++11 -g")

project(pcapDetector)


include(FindPCAP.cmake)

INCLUDE(FindProtobuf)
FIND_PACKAGE(Protobuf REQUIRED)
INCLUDE_DIRECTORIES(${PROTOBUF_INCLUDE_DIR})
PROTOBUF_GENERATE_CPP(PROTO_SRC PROTO_HEADER ./protobuf/config.proto)
ADD_LIBRARY(proto ${PROTO_HEADER} ${PROTO_SRC})

add_executable(pcapDetector main.cpp  EthernetHeader.cpp  IPHeader.cpp  TCPHeader.cpp  UDPHeader.cpp)





target_link_libraries(pcapDetector ${PCAP_LIBRARY} ${PROTOBUF_LIBRARY})