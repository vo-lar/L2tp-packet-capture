#include "l2tp.h"

/*tcp分析包*/
bool tcp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content)
{
    struct tcp_header* tcp_protocol;     /*tcp协议变量*/
    u_char flags;                          /*标记*/
    int header_length;                  /*头长度*/
    u_short source_port;           /*源端口*/
    u_short destination_port;   /*目的端口*/
    u_short windows;                /*窗口大小*/
    u_short urgent_pointer;     /*紧急指针*/
    u_int sequence;                 /*序列号*/
    u_int acknowledgement;   /*确认号*/
    u_int16_t   checksum;       /*检验和*/
    tcp_protocol = (struct tcp_header*)(packet_content + 14 + 20);  /*获得tcp首部内容*/
    source_port = ntohs(tcp_protocol->tcp_source_port);                  /*获得源端口号*/
    destination_port = ntohs(tcp_protocol->tcp_destination_port); /*获得目的端口号*/
    header_length = tcp_protocol->tcp_offset * 4;                            /*获得首部长度*/
    sequence = ntohl(tcp_protocol->tcp_acknowledgement);        /*获得序列号*/
    acknowledgement = ntohl(tcp_protocol->tcp_ack);
    windows = ntohs(tcp_protocol->tcp_windows);
    urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);
    flags = tcp_protocol->tcp_flags;
    checksum = ntohs(tcp_protocol->tcp_checksum);
    printf("\n==========    运输层（TCP协议）    ==========\n");
    printf("源端口：\t %d\n", source_port);
    printf("目的端口：\t %d\n", destination_port);

    int min = (destination_port < source_port) ? destination_port : source_port;
    cout << "应用层协议是：\t";
    switch (min)
    {
        case 80:printf(" http 用于万维网（WWW）服务的超文本传输协议（HTTP）");
            break;

        case 21:printf(" ftp 文件传输协议（FTP）");
            break;

        case 23:printf(" telnet Telnet 服务  ");
            break;

        case 25:printf(" smtp 简单邮件传输协议（SMTP）");
            break;

        case 110:printf(" pop3 邮局协议版本3 ");
            break;
        case 443:printf(" https 安全超文本传输协议（HTTP） ");
            break;

        default:printf("【其他类型】 ");
            break;
    }
    cout << endl;
    printf("序列号：\t %u \n", sequence);
    printf("确认号：\t%u \n", acknowledgement);
    printf("首部长度：\t%d \n", header_length);
    printf("保留字段：\t%d \n", tcp_protocol->tcp_reserved);
    printf("控制位：");
    if (flags & 0x08)  printf("\t【推送 PSH】");
    if (flags & 0x10)  printf("\t【确认 ACK】 ");
    if (flags & 0x02)  printf("\t【同步 SYN】");
    if (flags & 0x20)  printf("\t【紧急 URG】");
    if (flags & 0x01)  printf("\t【终止 FIN】");
    if (flags & 0x04)  printf("\t【复位 RST】");

    printf("\n");
    printf("窗口大小 :\t%d \n", windows);
    printf("检验和 :\t%d\n", checksum);
    printf("紧急指针字段 :\t%d\n", urgent_pointer);
    return 1;
}

/*下边实现IP数据包分析的函数定义ethernet_protocol_packet_callback*/
bool ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content)
{
    struct ip_header* ip_protocol;   /*ip协议变量*/
    u_int  header_length;    /*长度*/
    u_int  offset;                   /*片偏移*/
    u_char  tos;                     /*服务类型*/
    u_int16_t checksum;    /*首部检验和*/
    ip_protocol = (struct ip_header*)(packet_content + 14); /*获得ip数据包的内容去掉以太头部*/
    checksum = ntohs(ip_protocol->ip_checksum);      /*获得校验和*/
    header_length = ip_protocol->ip_header_length * 4; /*获得长度*/
    tos = ip_protocol->ip_tos;    /*获得tos*/
    offset = ntohs(ip_protocol->ip_off);   /*获得偏移量*/
    //cout << "\n传输层协议是:\t";

    bool ret = 0;
    switch (ip_protocol->ip_protocol)
    {
        case 6:
            //printf("TCP\n");
            //ret = tcp_protocol_packet_callback(argument, packet_header, packet_content);
            break; /*协议类型是6代表TCP*/
        case 17:
            //printf("UDP\n");
            ret = udp_protocol_packet_callback(argument, packet_header, packet_content);
            break;/*17代表UDP*/
        case 1:
            printf("ICMP\n");
            break;/*代表ICMP*/
        case 2:
            printf("IGMP\n");
            break;/*代表IGMP*/
        default:break;
    }
    if (ret) {
        printf("\n网络层（IP协议）\n");
        printf("IP版本:\t\tIPv%d\n", ip_protocol->ip_version);
        printf("IP协议首部长度:\t%d\n", header_length);
        printf("服务类型:\t%d\n", tos);
        printf("总长度:\t\t%d\n", ntohs(ip_protocol->ip_length));/*获得总长度*/
        printf("标识:\t\t%d\n", ntohs(ip_protocol->ip_id));  /*获得标识*/
        printf("片偏移:\t\t%d\n", (offset & 0x1fff) * 8);    /*offset*/
        printf("生存时间:\t%d\n", ip_protocol->ip_ttl);     /*获得ttl*/
        printf("首部检验和:\t%d\n", checksum);
        printf("源IP:\t%s\n", inet_ntoa(ip_protocol->ip_source_address));          /*获得源ip地址*/
        printf("目的IP:\t%s\n", inet_ntoa(ip_protocol->ip_destination_address));/*获得目的ip地址*/
        printf("协议号:\t%d\n", ip_protocol->ip_protocol);         /*获得协议类型*/
    }
    return ret;
}

/*udp分析*/
bool udp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content)
{
    udp_Header* udp_protocal;
    
    ip_header* ih = (ip_header*)(packet_content + 14);
    udp_protocal = (udp_Header*)((u_char*)ih + ih->ip_header_length * 4);
    u_int16_t dport = ntohs(udp_protocal->dport);
    u_int16_t sport = ntohs(udp_protocal->sport);
    if (dport == 4500 || sport == 4500) {
        cout << "l2tp协议经过IpSec封装变为了esp，无法继续解析" << endl;
        cout << "UDP: " << endl;
        cout << "源端口: " << ntohs(udp_protocal->sport) << endl;
        cout << "目的端口: " << ntohs(udp_protocal->dport) << endl;
        cout << "长度: " << ntohs(udp_protocal->len) << endl;
        cout << "校验: " << ntohs(udp_protocal->crc) << endl;
        return 1;
    }
    if ((dport != 1701 && sport != 1701)) {
        //cout << "不是l2tp协议" << endl;
        return 0;
    }
    
    u_char* p = (u_char*)udp_protocal + 8;
    l2tp_protocol_packet_callback(p);

    cout << "UDP: " << endl;
    cout << "源端口: " << ntohs(udp_protocal->sport) << endl;
    cout << "目的端口: " << ntohs(udp_protocal->dport) << endl;
    cout << "长度: " << ntohs(udp_protocal->len) << endl;
    cout << "校验: " << ntohs(udp_protocal->crc) << endl;

    return 1;
}

/*l2tp分析*/
void l2tp_protocol_packet_callback(u_char* p)
{
    cout << "L2TP: " << endl;
    bool type = ((ntohs(*(u_short*)p) & 0x8000) >> 15);
    bool len_bit = ((ntohs(*(u_short*)p) & 0x4000) >> 14);
    bool seq_bit = ((ntohs(*(u_short*)p) & 0x0800) >> 11);
    bool offset_bit = ((ntohs(*(u_short*)p) & 0x0200) >> 9);
    bool pri_bit = ((ntohs(*(u_short*)p) & 0x0100) >> 8);
    int version = (ntohs(*(u_short*)p) & 0x000f);
    cout << "类型: " << type << endl;
    cout << "长度在位标志: " << len_bit << endl;
    cout << "序列号: " << seq_bit << endl;
    cout << "偏移量: " << offset_bit << endl;
    cout << "优先级: " << pri_bit << endl;
    cout << "版本: " << version << endl;
    int l2tp_len = 2;
    if (len_bit) {
        u_short len = ntohs(*(u_short*)(p + l2tp_len));
        cout << "文本长度: " << len << endl;
        l2tp_len += 2;
    }
    u_short tunnel_id = ntohs(*(u_short*)(p + l2tp_len));
    u_short session_id = ntohs(*(u_short*)(p + l2tp_len + 2));
    l2tp_len += 4;
    cout << "隧道标识符: " << tunnel_id << endl;
    cout << "会话标识符: " << session_id << endl;
    if (seq_bit) {
        u_short Ns = ntohs(*(u_short*)(p + l2tp_len));
        u_short Nr = ntohs(*(u_short*)(p + l2tp_len + 2));
        cout << "当前消息序列号: " << Ns << endl;
        cout << "希望接收消息序列号: " << Nr << endl;
        l2tp_len += 4;
    }
    if (offset_bit) {
        u_short offset_size = ntohs(*(u_short*)(p + l2tp_len));
        u_short offset_pad = ntohs(*(u_short*)(p + l2tp_len + 2));
        cout << "偏移量: " << offset_size << endl;
        cout << "补充位: " << offset_pad << endl;
        l2tp_len += 4;
    }
}

/*以太网分析*/
void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    u_short ethernet_type;                                     /*以太网协议类型*/
    struct ethernet_header* ethernet_protocol;  /*以太网协议变量*/
    u_char* mac_string;
    static int packet_number = 1; 
    ethernet_protocol = (struct ethernet_header*)packet_content;  /*获得以太网协议数据内容*/
    ethernet_type = ntohs(ethernet_protocol->ether_type); /*获得以太网类型*/
    bool ret = 0;
    switch (ethernet_type)
    {
        case 0x0800:
            /*如果上层是IPv4ip协议,就调用分析ip协议的函数对ip包进行贩治*/
            ret = ip_protocol_packet_callback(argument, packet_header, packet_content);
            break;
        default:
            //cout << "不是ipv4协议，暂无法解析" << endl;
            break;
    }
    if (ret) {

        printf("以太网类型为 :%04x\n", ethernet_type);
        /*获得Mac源地址*/
        printf("Mac源地址:\t");
        mac_string = ethernet_protocol->ether_shost;
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

        /*获得Mac目的地址*/
        printf("Mac目的地址:\t");
        mac_string = ethernet_protocol->ether_dhost;
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
        
        printf("\n\n");
        printf("\t============================================================\n");
        printf("\t===============第 %03d 个L2TP数据包已被捕获===================\n", packet_number++);
        printf("\t============================================================\n");
        
    }
    if (packet_number > MAX_LOOP) exit(0);
    return;
    
}

