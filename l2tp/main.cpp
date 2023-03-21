#include <iostream>
#include <string>
#include <pcap.h>
#include <winsock.h>
#include "l2tp.h"

using namespace std;

int main()
{
    cout << "l2tp����\n";
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum = 0;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* ����������б� */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    /* ��ӡ������Ϣ */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nû�з��ֽӿ�!ȷ����װ��LibPcap.\n");
        return -1;
    }

    printf("\n������Ҫѡ��򿪵������� (1-%d)��:", i);
    cin >> inum;               //����Ҫѡ��򿪵�������

    if (inum < 1 || inum > i) //�жϺŵĺϷ���
    {
        printf("\n�����ų�����Χ.\n");
        /*�ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* �ҵ�Ҫѡ��������ṹ */
    for (d = alldevs, i = 0; i < inum - 1 && d != nullptr; d = d->next, i++);

    if (d == nullptr) {
        printf("\n�����ų�����Χ.\n");
        /*�ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return -1;
    }
    /* ��ѡ������� */
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
    {
        cout << "\n�޷���������.\t %s ����LibPcap֧��\n";
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\n���� %s...\n", d->description);
    /* ���ڣ����ǲ�����Ҫ�豸�б�, �ͷ��� */
    pcap_freealldevs(alldevs);
    int cnt = -1;
    cout << "\n����Ҫ����L2TP���ݰ���\n";
    //cin >> cnt;
    /* ��ʼ�Իص��ķ�ʽ�����
    �������ƣ�int pcap_loop(pcap_t * p,int cnt, pcap_handler callback, uchar * user);
    �������ܣ��������ݰ�,������Ӧpcap_open_live()�������õĳ�ʱʱ��
    */
    pcap_loop(adhandle, cnt, ethernet_protocol_packet_callback, NULL);
    cout << "\n\t����L2TP���ݰ�����\n";
    return 0;
}
