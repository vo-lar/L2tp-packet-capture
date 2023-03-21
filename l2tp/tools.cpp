#include "l2tp.h"

/*tcp������*/
bool tcp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content)
{
    struct tcp_header* tcp_protocol;     /*tcpЭ�����*/
    u_char flags;                          /*���*/
    int header_length;                  /*ͷ����*/
    u_short source_port;           /*Դ�˿�*/
    u_short destination_port;   /*Ŀ�Ķ˿�*/
    u_short windows;                /*���ڴ�С*/
    u_short urgent_pointer;     /*����ָ��*/
    u_int sequence;                 /*���к�*/
    u_int acknowledgement;   /*ȷ�Ϻ�*/
    u_int16_t   checksum;       /*�����*/
    tcp_protocol = (struct tcp_header*)(packet_content + 14 + 20);  /*���tcp�ײ�����*/
    source_port = ntohs(tcp_protocol->tcp_source_port);                  /*���Դ�˿ں�*/
    destination_port = ntohs(tcp_protocol->tcp_destination_port); /*���Ŀ�Ķ˿ں�*/
    header_length = tcp_protocol->tcp_offset * 4;                            /*����ײ�����*/
    sequence = ntohl(tcp_protocol->tcp_acknowledgement);        /*������к�*/
    acknowledgement = ntohl(tcp_protocol->tcp_ack);
    windows = ntohs(tcp_protocol->tcp_windows);
    urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);
    flags = tcp_protocol->tcp_flags;
    checksum = ntohs(tcp_protocol->tcp_checksum);
    printf("\n==========    ����㣨TCPЭ�飩    ==========\n");
    printf("Դ�˿ڣ�\t %d\n", source_port);
    printf("Ŀ�Ķ˿ڣ�\t %d\n", destination_port);

    int min = (destination_port < source_port) ? destination_port : source_port;
    cout << "Ӧ�ò�Э���ǣ�\t";
    switch (min)
    {
        case 80:printf(" http ������ά����WWW������ĳ��ı�����Э�飨HTTP��");
            break;

        case 21:printf(" ftp �ļ�����Э�飨FTP��");
            break;

        case 23:printf(" telnet Telnet ����  ");
            break;

        case 25:printf(" smtp ���ʼ�����Э�飨SMTP��");
            break;

        case 110:printf(" pop3 �ʾ�Э��汾3 ");
            break;
        case 443:printf(" https ��ȫ���ı�����Э�飨HTTP�� ");
            break;

        default:printf("���������͡� ");
            break;
    }
    cout << endl;
    printf("���кţ�\t %u \n", sequence);
    printf("ȷ�Ϻţ�\t%u \n", acknowledgement);
    printf("�ײ����ȣ�\t%d \n", header_length);
    printf("�����ֶΣ�\t%d \n", tcp_protocol->tcp_reserved);
    printf("����λ��");
    if (flags & 0x08)  printf("\t������ PSH��");
    if (flags & 0x10)  printf("\t��ȷ�� ACK�� ");
    if (flags & 0x02)  printf("\t��ͬ�� SYN��");
    if (flags & 0x20)  printf("\t������ URG��");
    if (flags & 0x01)  printf("\t����ֹ FIN��");
    if (flags & 0x04)  printf("\t����λ RST��");

    printf("\n");
    printf("���ڴ�С :\t%d \n", windows);
    printf("����� :\t%d\n", checksum);
    printf("����ָ���ֶ� :\t%d\n", urgent_pointer);
    return 1;
}

/*�±�ʵ��IP���ݰ������ĺ�������ethernet_protocol_packet_callback*/
bool ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content)
{
    struct ip_header* ip_protocol;   /*ipЭ�����*/
    u_int  header_length;    /*����*/
    u_int  offset;                   /*Ƭƫ��*/
    u_char  tos;                     /*��������*/
    u_int16_t checksum;    /*�ײ������*/
    ip_protocol = (struct ip_header*)(packet_content + 14); /*���ip���ݰ�������ȥ����̫ͷ��*/
    checksum = ntohs(ip_protocol->ip_checksum);      /*���У���*/
    header_length = ip_protocol->ip_header_length * 4; /*��ó���*/
    tos = ip_protocol->ip_tos;    /*���tos*/
    offset = ntohs(ip_protocol->ip_off);   /*���ƫ����*/
    //cout << "\n�����Э����:\t";

    bool ret = 0;
    switch (ip_protocol->ip_protocol)
    {
        case 6:
            //printf("TCP\n");
            //ret = tcp_protocol_packet_callback(argument, packet_header, packet_content);
            break; /*Э��������6����TCP*/
        case 17:
            //printf("UDP\n");
            ret = udp_protocol_packet_callback(argument, packet_header, packet_content);
            break;/*17����UDP*/
        case 1:
            printf("ICMP\n");
            break;/*����ICMP*/
        case 2:
            printf("IGMP\n");
            break;/*����IGMP*/
        default:break;
    }
    if (ret) {
        printf("\n����㣨IPЭ�飩\n");
        printf("IP�汾:\t\tIPv%d\n", ip_protocol->ip_version);
        printf("IPЭ���ײ�����:\t%d\n", header_length);
        printf("��������:\t%d\n", tos);
        printf("�ܳ���:\t\t%d\n", ntohs(ip_protocol->ip_length));/*����ܳ���*/
        printf("��ʶ:\t\t%d\n", ntohs(ip_protocol->ip_id));  /*��ñ�ʶ*/
        printf("Ƭƫ��:\t\t%d\n", (offset & 0x1fff) * 8);    /*offset*/
        printf("����ʱ��:\t%d\n", ip_protocol->ip_ttl);     /*���ttl*/
        printf("�ײ������:\t%d\n", checksum);
        printf("ԴIP:\t%s\n", inet_ntoa(ip_protocol->ip_source_address));          /*���Դip��ַ*/
        printf("Ŀ��IP:\t%s\n", inet_ntoa(ip_protocol->ip_destination_address));/*���Ŀ��ip��ַ*/
        printf("Э���:\t%d\n", ip_protocol->ip_protocol);         /*���Э������*/
    }
    return ret;
}

/*udp����*/
bool udp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr*
    packet_header, const u_char* packet_content)
{
    udp_Header* udp_protocal;
    
    ip_header* ih = (ip_header*)(packet_content + 14);
    udp_protocal = (udp_Header*)((u_char*)ih + ih->ip_header_length * 4);
    u_int16_t dport = ntohs(udp_protocal->dport);
    u_int16_t sport = ntohs(udp_protocal->sport);
    if (dport == 4500 || sport == 4500) {
        cout << "l2tpЭ�龭��IpSec��װ��Ϊ��esp���޷���������" << endl;
        cout << "UDP: " << endl;
        cout << "Դ�˿�: " << ntohs(udp_protocal->sport) << endl;
        cout << "Ŀ�Ķ˿�: " << ntohs(udp_protocal->dport) << endl;
        cout << "����: " << ntohs(udp_protocal->len) << endl;
        cout << "У��: " << ntohs(udp_protocal->crc) << endl;
        return 1;
    }
    if ((dport != 1701 && sport != 1701)) {
        //cout << "����l2tpЭ��" << endl;
        return 0;
    }
    
    u_char* p = (u_char*)udp_protocal + 8;
    l2tp_protocol_packet_callback(p);

    cout << "UDP: " << endl;
    cout << "Դ�˿�: " << ntohs(udp_protocal->sport) << endl;
    cout << "Ŀ�Ķ˿�: " << ntohs(udp_protocal->dport) << endl;
    cout << "����: " << ntohs(udp_protocal->len) << endl;
    cout << "У��: " << ntohs(udp_protocal->crc) << endl;

    return 1;
}

/*l2tp����*/
void l2tp_protocol_packet_callback(u_char* p)
{
    cout << "L2TP: " << endl;
    bool type = ((ntohs(*(u_short*)p) & 0x8000) >> 15);
    bool len_bit = ((ntohs(*(u_short*)p) & 0x4000) >> 14);
    bool seq_bit = ((ntohs(*(u_short*)p) & 0x0800) >> 11);
    bool offset_bit = ((ntohs(*(u_short*)p) & 0x0200) >> 9);
    bool pri_bit = ((ntohs(*(u_short*)p) & 0x0100) >> 8);
    int version = (ntohs(*(u_short*)p) & 0x000f);
    cout << "����: " << type << endl;
    cout << "������λ��־: " << len_bit << endl;
    cout << "���к�: " << seq_bit << endl;
    cout << "ƫ����: " << offset_bit << endl;
    cout << "���ȼ�: " << pri_bit << endl;
    cout << "�汾: " << version << endl;
    int l2tp_len = 2;
    if (len_bit) {
        u_short len = ntohs(*(u_short*)(p + l2tp_len));
        cout << "�ı�����: " << len << endl;
        l2tp_len += 2;
    }
    u_short tunnel_id = ntohs(*(u_short*)(p + l2tp_len));
    u_short session_id = ntohs(*(u_short*)(p + l2tp_len + 2));
    l2tp_len += 4;
    cout << "�����ʶ��: " << tunnel_id << endl;
    cout << "�Ự��ʶ��: " << session_id << endl;
    if (seq_bit) {
        u_short Ns = ntohs(*(u_short*)(p + l2tp_len));
        u_short Nr = ntohs(*(u_short*)(p + l2tp_len + 2));
        cout << "��ǰ��Ϣ���к�: " << Ns << endl;
        cout << "ϣ��������Ϣ���к�: " << Nr << endl;
        l2tp_len += 4;
    }
    if (offset_bit) {
        u_short offset_size = ntohs(*(u_short*)(p + l2tp_len));
        u_short offset_pad = ntohs(*(u_short*)(p + l2tp_len + 2));
        cout << "ƫ����: " << offset_size << endl;
        cout << "����λ: " << offset_pad << endl;
        l2tp_len += 4;
    }
}

/*��̫������*/
void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    u_short ethernet_type;                                     /*��̫��Э������*/
    struct ethernet_header* ethernet_protocol;  /*��̫��Э�����*/
    u_char* mac_string;
    static int packet_number = 1; 
    ethernet_protocol = (struct ethernet_header*)packet_content;  /*�����̫��Э����������*/
    ethernet_type = ntohs(ethernet_protocol->ether_type); /*�����̫������*/
    bool ret = 0;
    switch (ethernet_type)
    {
        case 0x0800:
            /*����ϲ���IPv4ipЭ��,�͵��÷���ipЭ��ĺ�����ip�����з���*/
            ret = ip_protocol_packet_callback(argument, packet_header, packet_content);
            break;
        default:
            //cout << "����ipv4Э�飬���޷�����" << endl;
            break;
    }
    if (ret) {

        printf("��̫������Ϊ :%04x\n", ethernet_type);
        /*���MacԴ��ַ*/
        printf("MacԴ��ַ:\t");
        mac_string = ethernet_protocol->ether_shost;
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

        /*���MacĿ�ĵ�ַ*/
        printf("MacĿ�ĵ�ַ:\t");
        mac_string = ethernet_protocol->ether_dhost;
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
        
        printf("\n\n");
        printf("\t============================================================\n");
        printf("\t===============�� %03d ��L2TP���ݰ��ѱ�����===================\n", packet_number++);
        printf("\t============================================================\n");
        
    }
    if (packet_number > MAX_LOOP) exit(0);
    return;
    
}

