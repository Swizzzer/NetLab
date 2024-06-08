#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // 初始化txbuf
    buf_init(&txbuf, req_buf->len);
    // 将req_buf的数据复制到txbuf
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    // 将txbuf的数据转换为icmp_hdr类型
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr_t *req_hdr = (icmp_hdr_t *)req_buf->data;
    // 将icmp_hdr的type设置为ICMP_TYPE_ECHO_REPLY
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
    // 将icmp_hdr的code设置为0
    icmp_hdr->code = 0;
    // 将icmp_hdr的id16设置为req_hdr的id16
    icmp_hdr->id16 = req_hdr->id16;
    // 将icmp_hdr的seq16设置为req_hdr的seq16
    icmp_hdr->seq16 = req_hdr->seq16;
    // 将icmp_hdr的checksum16设置为0
    icmp_hdr->checksum16 = 0;
    // 将icmp_hdr的checksum16设置为swap16后的值
    icmp_hdr->checksum16 = swap16(checksum16((uint16_t *)txbuf.data, txbuf.len));
    // 将txbuf的数据和src_ip发送出去
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // head check
    if (buf->len < sizeof(icmp_hdr_t))
        return;

    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;

    if (hdr->type == ICMP_TYPE_ECHO_REQUEST)
    {
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // 定义一个指向接收缓冲区的指针
    uint8_t *data = recv_buf->data;
    // 计算总大小
    int total_size = sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8;
    // 获取IP头部的长度
    int len = ((ip_hdr_t *)(recv_buf->data))->hdr_len;
    // 将IP头部的长度乘以4，加上8，得到数据部分的长度
    len = len * 4 + 8;
    // 初始化发送缓冲区
    buf_init(&txbuf, len);
    // 将接收缓冲区的数据复制到发送缓冲区
    memcpy(txbuf.data, data, len);
    // 在发送缓冲区添加ICMP头部
    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    // 定义一个指向ICMP头部的指针
    icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
    // 设置ICMP头部的类型、代码、校验和等参数
    *hdr = (icmp_hdr_t){
        .type = ICMP_TYPE_UNREACH,
        .code = code,
        .checksum16 = 0,
        .id16 = 0,
        .seq16 = 0,
    };
    // 将ICMP头部的校验和设置为接收缓冲区数据的校验和
    hdr->checksum16 = swap16(checksum16((uint16_t *)txbuf.data, total_size));

    // 将发送缓冲区的数据发送出去
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init()
{
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}