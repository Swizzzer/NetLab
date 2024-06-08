#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // 长度检测
    if (buf->len < sizeof(ip_hdr_t))
    {
        return;
    }
    // 报头检测
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    if (ip_hdr->version != IP_VERSION_4 || swap16(ip_hdr->total_len16) > buf->len)
    {
        return;
    }
    uint16_t checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    // 计算校验和
    uint16_t checksum_tmp = checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t));
    if (swap16(checksum) != checksum_tmp)
    {
        return;
    }
    // 恢复校验和
    ip_hdr->hdr_checksum16 = checksum;
    // 丢弃非本机IP的包
    if (memcmp(net_if_ip, ip_hdr->dst_ip, NET_IP_LEN) != 0)
    {
        return;
    }
    if (buf->len > swap16(ip_hdr->total_len16))
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));
    // 不能识别的协议类型返回不可达
    if (!(ip_hdr->protocol == NET_PROTOCOL_UDP ||
          ip_hdr->protocol == NET_PROTOCOL_ICMP))
    {
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
    buf_remove_header(buf, sizeof(ip_hdr_t));
    net_in(buf, ip_hdr->protocol, ip_hdr->src_ip);
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO

    ip_hdr_t packet;

    // 填写ip数据报头
    packet.hdr_len = 5;
    packet.version = IP_VERSION_4;
    packet.tos = 0;
    packet.total_len16 = swap16(buf->len + sizeof(ip_hdr_t));
    packet.id16 = swap16(id);
    if (mf)
    {
        // 当存在下一分片时，标志位为001
        packet.flags_fragment16 = swap16(0x2000 | offset);
    }
    else
    {
        // 不存在下一分片时，标志位为000
        packet.flags_fragment16 = swap16(offset);
    }
    packet.protocol = protocol;
    packet.ttl = IP_DEFALUT_TTL;
    // 先将校验和置0以运算校验和
    packet.hdr_checksum16 = swap16(0);
    memcpy(packet.dst_ip, ip, NET_IP_LEN);
    memcpy(packet.src_ip, net_if_ip, NET_IP_LEN);
    packet.hdr_checksum16 = swap16(checksum16((uint16_t *)(&packet), sizeof(ip_hdr_t)));
    buf_add_header(buf, sizeof(ip_hdr_t));
    memcpy(buf->data, &packet, sizeof(ip_hdr_t));
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    static uint16_t ip_id = 0;

    // 数据长度小于1480直接发送
    if (buf->len <= ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t))
    {
        ip_fragment_out(buf, ip, protocol, ip_id, 0, 0);
        ip_id += 1;
    }
    else
    {
        buf_t ip_buf;
        uint16_t len_sum = 0;

        // 每次分割1480长度的切片
        while (buf->len > ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t))
        {
            buf_init(&ip_buf, ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t));
            memcpy(ip_buf.data, buf->data, ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t));
            ip_fragment_out(&ip_buf, ip, protocol, ip_id, len_sum / IP_HDR_OFFSET_PER_BYTE, 1);
            buf_remove_header(buf, ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t));
            len_sum += ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
        }

        // 发送最后一个切片
        if (buf->len != 0)
        {
            buf_init(&ip_buf, buf->len);
            memcpy(ip_buf.data, buf->data, buf->len);
            ip_fragment_out(&ip_buf, ip, protocol, ip_id, len_sum / IP_HDR_OFFSET_PER_BYTE, 0);
            ip_id += 1;
        }
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}