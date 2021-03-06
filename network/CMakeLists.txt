cmake_minimum_required(VERSION 3.17.3)
project(network C)

set(CMAKE_C_STANDARD 99)

include_directories(winpcap/Include)
link_directories(winpcap/Lib)

add_executable(network main.c)
add_executable(ipv4 ipv4.c)
add_executable(icmp icmp.c)
add_executable(udp udp.c)
add_executable(udpclient udp/udpclient.c)
add_executable(udpserver udp/udpserver.c)
add_executable(tcp tcp.c)
add_executable(tcpx tcpx.c)
add_executable(tcpclient tcp/tcpclient.c)
add_executable(tcpserver tcp/tcpserver.c)
add_executable(http http.c)

target_link_libraries(network ws2_32 wpcap)
target_link_libraries(ipv4 ws2_32)
target_link_libraries(icmp ws2_32)
target_link_libraries(udp ws2_32)
target_link_libraries(udpclient ws2_32)
target_link_libraries(udpserver ws2_32)
target_link_libraries(tcp ws2_32 wpcap)
target_link_libraries(tcpx ws2_32)
target_link_libraries(tcpclient ws2_32)
target_link_libraries(tcpserver ws2_32)
target_link_libraries(http ws2_32)