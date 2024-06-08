#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    buf_t *buf = &txbuf;
    buf_init(buf, sizeof(arp_pkt_t));  //初始化txbuf
    arp_pkt_t packet = arp_init_pkt;
    packet.opcode16 = swap16(ARP_REQUEST);  //填充opcode
    memcpy(packet.target_ip, target_ip, NET_IP_LEN);  //填充target_ip
    memcpy(buf->data, &packet, sizeof(arp_pkt_t));
    ethernet_out(buf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    buf_t *buf = &txbuf;
    buf_init(buf, sizeof(arp_pkt_t));  //初始化txbuf
    arp_pkt_t packet = arp_init_pkt;
    packet.opcode16 = swap16(ARP_REPLY);  //填充opcode
    memcpy(packet.target_ip, target_ip, NET_IP_LEN);  //填充target_ip
    memcpy(packet.target_mac, target_mac, NET_MAC_LEN);  //填充target_mac
    memcpy(buf->data, &packet, sizeof(arp_pkt_t));
    ethernet_out(buf, target_mac, NET_PROTOCOL_ARP); 
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
/**
 * @brief 处理一个收到的arp数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // arp数据包的最小长度
    if(buf->len < sizeof(arp_pkt_t)) return;
    arp_pkt_t* arp = (arp_pkt_t*) buf->data;
    // 硬件类型
    if(arp->hw_type16 != swap16(ARP_HW_ETHER)) return;
    // 协议类型
    if(arp->pro_type16 != swap16(NET_PROTOCOL_IP)) return;
    // 硬件地址长
    if(arp->hw_len != NET_MAC_LEN) return;
    // 协议地址长
    if(arp->pro_len != NET_IP_LEN) return;
    // opcode，ARP请求，ARP响应，ARP错误
    if(arp->opcode16 != swap16(ARP_HW_ETHER) && arp->opcode16 != swap16(ARP_REPLY) && arp->opcode16 != swap16(ARP_REQUEST)) return;
    // 将目标ip和mac地址添加到arp表中
    map_set(&arp_table, arp->sender_ip, arp->sender_mac);
    // 查看缓存中是否已经存在该ip的arp数据包
    buf_t* map_buf = map_get(&arp_buf, (void*) arp->sender_ip);
    if(map_buf == NULL){
        // 如果是arp请求，并且是对本机的arp请求
        if(arp->opcode16 == swap16(ARP_REQUEST)){
            int flag = 1;
            for(int i = 0; i < NET_IP_LEN; i++){
                if(arp->target_ip[i] != net_if_ip[i]){
                    flag =  0;
                    break;
                }
            }
            if(flag){
                arp_resp(arp->sender_ip, src_mac);
            }
        }
    }
    else{
        // 如果是arp响应，直接将缓存中的arp数据包发送出去
        ethernet_out(map_buf, arp->sender_mac, NET_PROTOCOL_IP);
        // 将缓存中的arp数据包删除
        map_delete(&arp_buf, arp->sender_ip);
    }
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    uint8_t *target_mac = map_get(&arp_table, ip);
    if(target_mac == NULL){
        buf_t *cache_buf = map_get(&arp_buf, ip);
        if(cache_buf != NULL){
            return;
        }else{
            //设置目标ip的map缓存
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }else{
        ethernet_out(buf, target_mac, NET_PROTOCOL_IP);
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}