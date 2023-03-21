#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <iostream>
#include <pcap.h>

using namespace std;

#define MAX_LOOP 100

/*以太网*/
struct ethernet_header
{
    u_int8_t ether_dhost[6];  /*目的以太地址*/
    u_int8_t ether_shost[6];  /*源以太网地址*/
    u_int16_t ether_type;      /*以太网类型*/
};

/*ip*/
typedef u_int32_t in_addr_t;
struct ip_header
{
#ifdef WORKS_BIGENDIAN
    u_int8_t ip_version : 4,    /*version:4*/
        ip_header_length : 4; /*IP协议首部长度Header Length*/
#else
    u_int8_t ip_header_length : 4,
        ip_version : 4;
#endif
    u_int8_t ip_tos;         /*服务类型Differentiated Services  Field*/
    u_int16_t ip_length;  /*总长度Total Length*/
    u_int16_t ip_id;         /*标识identification*/
    u_int16_t ip_off;        /*片偏移*/
    u_int8_t ip_ttl;            /*生存时间Time To Live*/
    u_int8_t ip_protocol;        /*协议类型（TCP或者UDP协议）*/
    u_int16_t ip_checksum;  /*首部检验和*/
    struct in_addr  ip_source_address; /*源IP*/
    struct in_addr  ip_destination_address; /*目的IP*/
    u_int   op_pad;       // Option + Padding
};

/*tcp*/
struct tcp_header
{
    u_int16_t tcp_source_port;		  //源端口号

    u_int16_t tcp_destination_port;	//目的端口号

    u_int32_t tcp_acknowledgement;	//序号

    u_int32_t tcp_ack;	//确认号字段
#ifdef WORDS_BIGENDIAN
    u_int8_t tcp_offset : 4,
        tcp_reserved : 4;
#else
    u_int8_t tcp_reserved : 4,
        tcp_offset : 4;
#endif
    u_int8_t tcp_flags;
    u_int16_t tcp_windows;	//窗口字段
    u_int16_t tcp_checksum;	//检验和
    u_int16_t tcp_urgent_pointer;	//紧急指针字段
};

/*udp*/
struct udp_Header {
    u_short sport;       // Source port
    u_short dport;       // Destination port
    u_int16_t len;         // Datagram length
    u_int16_t crc;         // Checksum
};

/*l2tp*/
struct L2tp {
    u_int16_t flags_ver;
    u_int16_t len;
    u_int16_t tunnel_id;
    u_int16_t session_id;
    u_int16_t Nr;
    u_int16_t Ns;
    u_int16_t offset_size;
    u_int16_t offset_pad;
};

/*func*/

void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);

bool ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);

bool tcp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);

bool udp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);

void l2tp_protocol_packet_callback(u_char* p);