#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 *
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    // TO-DO
    int odd = 0;
    udp_hdr_t *udp_header = (udp_hdr_t *)buf->data;
    // 向缓冲区添加一个UDP头
    buf_add_header(buf, sizeof(udp_peso_hdr_t));
    // 获取UDP头
    udp_peso_hdr_t *udp_peso_header = (udp_peso_hdr_t *)buf->data;
    // 临时变量
    udp_peso_hdr_t temp = *udp_peso_header;
    // 将源IP地址复制到缓冲区
    memcpy(udp_peso_header->src_ip, src_ip, NET_IP_LEN);
    // 将目标IP地址复制到缓冲区
    memcpy(udp_peso_header->dst_ip, dst_ip, NET_IP_LEN);
    // 填充占位符
    udp_peso_header->placeholder = 0;
    // 设置协议类型为UDP
    udp_peso_header->protocol = NET_PROTOCOL_UDP;
    // 设置总长度
    udp_peso_header->total_len16 = udp_header->total_len16;
    if (buf->len % 2)
    {
        // 奇数数据，填充一个字节
        odd = 1;
        buf_add_padding(buf, 1);
    }
    uint16_t checksum = checksum16((uint16_t *)buf->data, buf->len);
    // 如果奇数，则去除缓冲区中的填充
    if (odd)
        buf_remove_padding(buf, 1);
    // 将临时值赋值给udp_peso_header
    *udp_peso_header = temp;
    // 去除缓冲区中的头
    buf_remove_header(buf, sizeof(udp_peso_hdr_t));
    // 返回校验和
    return checksum;
}

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    // 如果数据包的长度小于udp头部长度，则直接返回
    if (buf->len < sizeof(udp_hdr_t))
        return;
    // 获取udp头部的指针
    udp_hdr_t *udp_header = (udp_hdr_t *)buf->data;
    // 如果udp头部的总长度小于udp头部长度，则直接返回
    if (swap16(udp_header->total_len16) < sizeof(udp_hdr_t))
        return;
    // 获取udp头部的校验和
    uint16_t pre_checksum = udp_header->checksum16;
    // 将udp头部的校验和置为0
    udp_header->checksum16 = 0;
    // 计算udp校验和
    uint16_t now_checksum = udp_checksum(buf, src_ip, net_if_ip);
    // 如果计算出的校验和与原校验和不一致，则直接返回
    if (now_checksum != pre_checksum)
        return;
    // 将udp头部的校验和置为原校验和
    udp_header->checksum16 = pre_checksum;
    // 获取udp目标端口
    uint16_t dst_port = swap16(udp_header->dst_port16);
    // 获取udp处理函数
    udp_handler_t *handler = map_get(&udp_table, &dst_port);
    // 如果udp处理函数为空，则添加ip头，发送ICMP端口不可达报文
    if (!handler)
    {
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
    }
    // 否则，删除udp头部，调用udp处理函数
    else
    {
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (*handler)(buf->data, buf->len, src_ip, swap16(udp_header->dst_port16));
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // TO-DO
    // 向缓冲区添加一个UDP头
    buf_add_header(buf, sizeof(udp_hdr_t));
    // 获取UDP头指针
    udp_hdr_t *udp_header = (udp_hdr_t *)buf->data;
    // 设置源端口
    udp_header->src_port16 = swap16(src_port);
    // 设置目标端口
    udp_header->dst_port16 = swap16(dst_port);
    // 设置总长度
    udp_header->total_len16 = swap16(buf->len);
    // 设置校验和为0
    udp_header->checksum16 = 0;
    // 计算校验和
    udp_header->checksum16 = udp_checksum(buf, net_if_ip, dst_ip);
    // 发送数据包
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
    return;
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}