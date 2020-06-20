all : test

test: test.cpp
	g++  test.cpp ../EthernetHeader.cpp ../TCPHeader.cpp ../IPHeader.cpp ../UDPHeader.cpp ../SipHeader.cpp -std=c++11 -lgtest -lpthread -o test



clean:
	rm test