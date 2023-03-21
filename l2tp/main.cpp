#include <iostream>
#include <string>
#include <pcap.h>
#include <winsock.h>
#include "l2tp.h"

using namespace std;

int main()
{
    cout << "l2tp解析\n";
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum = 0;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 获得网卡的列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    /* 打印网卡信息 */
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
        printf("\n没有发现接口!确保安装了LibPcap.\n");
        return -1;
    }

    printf("\n【输入要选择打开的网卡号 (1-%d)】:", i);
    cin >> inum;               //输入要选择打开的网卡号

    if (inum < 1 || inum > i) //判断号的合法性
    {
        printf("\n网卡号超出范围.\n");
        /*释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 找到要选择的网卡结构 */
    for (d = alldevs, i = 0; i < inum - 1 && d != nullptr; d = d->next, i++);

    if (d == nullptr) {
        printf("\n网卡号超出范围.\n");
        /*释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
    /* 打开选择的网卡 */
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
    {
        cout << "\n无法打开适配器.\t %s 不被LibPcap支持\n";
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\n监听 %s...\n", d->description);
    /* 现在，我们不再需要设备列表, 释放它 */
    pcap_freealldevs(alldevs);
    int cnt = -1;
    cout << "\n【将要捕获L2TP数据包】\n";
    //cin >> cnt;
    /* 开始以回调的方式捕获包
    函数名称：int pcap_loop(pcap_t * p,int cnt, pcap_handler callback, uchar * user);
    函数功能：捕获数据包,不会响应pcap_open_live()函数设置的超时时间
    */
    pcap_loop(adhandle, cnt, ethernet_protocol_packet_callback, NULL);
    cout << "\n\t解析L2TP数据包结束\n";
    return 0;
}
