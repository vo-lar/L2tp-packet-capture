#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <iostream>
#include <pcap.h>

using namespace std;

#define MAX_LOOP 100

/*��̫��*/
struct ethernet_header
{
    u_int8_t ether_dhost[6];  /*Ŀ����̫��ַ*/
    u_int8_t ether_shost[6];  /*Դ��̫����ַ*/
    u_int16_t ether_type;      /*��̫������*/
};

/*ip*/
typedef u_int32_t in_addr_t;
struct ip_header
{
#ifdef WORKS_BIGENDIAN
    u_int8_t ip_version : 4,    /*version:4*/
        ip_header_length : 4; /*IPЭ���ײ�����Header Length*/
#else
    u_int8_t ip_header_length : 4,
        ip_version : 4;
#endif
    u_int8_t ip_tos;         /*��������Differentiated Services  Field*/
    u_int16_t ip_length;  /*�ܳ���Total Length*/
    u_int16_t ip_id;         /*��ʶidentification*/
    u_int16_t ip_off;        /*Ƭƫ��*/
    u_int8_t ip_ttl;            /*����ʱ��Time To Live*/
    u_int8_t ip_protocol;        /*Э�����ͣ�TCP����UDPЭ�飩*/
    u_int16_t ip_checksum;  /*�ײ������*/
    struct in_addr  ip_source_address; /*ԴIP*/
    struct in_addr  ip_destination_address; /*Ŀ��IP*/
    u_int   op_pad;       // Option + Padding
};

/*tcp*/
struct tcp_header
{
    u_int16_t tcp_source_port;		  //Դ�˿ں�

    u_int16_t tcp_destination_port;	//Ŀ�Ķ˿ں�

    u_int32_t tcp_acknowledgement;	//���

    u_int32_t tcp_ack;	//ȷ�Ϻ��ֶ�
#ifdef WORDS_BIGENDIAN
    u_int8_t tcp_offset : 4,
        tcp_reserved : 4;
#else
    u_int8_t tcp_reserved : 4,
        tcp_offset : 4;
#endif
    u_int8_t tcp_flags;
    u_int16_t tcp_windows;	//�����ֶ�
    u_int16_t tcp_checksum;	//�����
    u_int16_t tcp_urgent_pointer;	//����ָ���ֶ�
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