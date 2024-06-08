#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TO-DO

    if (buf->len < 14)
    {
        return;
    }
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    buf_remove_header(buf, sizeof(ether_hdr_t));
    net_in(buf, swap16(hdr->protocol16), hdr->src);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TO-DO
    // 如果buf的长度小于46，则向buf中添加填充
    if (buf->len < 46)
    {
        buf_add_padding(buf, 46 - buf->len);
    }
    // 在buf的开头添加以太帧头
    buf_add_header(buf, sizeof(ether_hdr_t));
    // 获取buf中的以太帧头
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    // 将mac地址复制到hdr->dst中
    memcpy(hdr->dst, mac, sizeof(hdr->dst));
    // 将NET_IF_MAC复制到hdr->src中
    uint8_t src[NET_MAC_LEN] = NET_IF_MAC;
    memcpy(hdr->src, src, sizeof(src));
    // 将protocol转换为网络字节顺序
    hdr->protocol16 = swap16(protocol);
    // 将buf发送出去
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
