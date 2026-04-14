#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/arp.h>
#include <net/tcp.h>


struct task_data 
{
    struct tasklet_struct tasklet;
    struct sk_buff *skb;
};

static struct nf_hook_ops inputHook;
static struct nf_hook_ops outputHook;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kormi Ka");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("0.01");

void send_func (unsigned long d)
{
    struct task_data *data = (struct task_data *)d;
    struct sk_buff* skb = data->skb;

    if (dev_queue_xmit(skb) != 0) 
    {
        pr_err("dev_queue_xmit failed\n");
        kfree_skb(skb);
    }
    kfree (data);
}

struct transfer_header
{
    uint8_t id;
    uint8_t last : 1;
    uint8_t type : 3;
    uint8_t reserv : 4;
};

static int find_mac_addr (uint8_t* mac, uint32_t ip, struct net_device *dev)
{
    struct neighbour *neigh = __ipv4_neigh_lookup(dev, ip);
    if (neigh && (neigh->nud_state & NUD_VALID)) 
    {
        memcpy(mac, neigh->ha, ETH_ALEN);
        neigh_release(neigh);
        return 0;
    }
    return -1;
}

struct list_data 
{
    uint32_t size;
    uint8_t* data;
    void* prev;
    void* next;
};

static void clear_list(struct list_data** end)
{
    struct list_data* cur = *end;
    
    while (cur )
    {
        struct list_data* prev = cur->prev;
        kfree(cur->data);
        kfree(cur);
        cur = prev;
    }
    
    *end = NULL;
}

static struct sk_buff* create_packet_input(struct sk_buff* in_packet,struct list_data* end, int size)
{     
    struct iphdr* ip_in = ip_hdr(in_packet);
    struct net_device *dev = dev_get_by_name(&init_net, "lo");
    if (!dev) 
    {
        pr_err("Cannot get loopback device\n");
        return NULL;
    }
    
    uint8_t mac_in[ETH_ALEN];
    if (find_mac_addr(mac_in, ip_in->saddr, in_packet->dev) < 0)
    {
        pr_info("MAC address not found for %pI4\n", &ip_in->saddr);
        return NULL;
    }
    struct icmphdr* icmp_in = icmp_hdr(in_packet);
    uint8_t* data_in = (uint8_t*)(icmp_in + 1);
    void* transport_in;
    uint32_t transport_header_len;
    
    int packet_size = sizeof(struct ethhdr) 
                    + sizeof(struct iphdr) 
                    + size;
    
    int hh_len = LL_RESERVED_SPACE(dev);
    int tlen = dev->needed_tailroom;
    struct sk_buff* skb = netdev_alloc_skb(dev, hh_len + tlen + size);

    if (unlikely(!skb)) 
    {
        pr_err("netdev_alloc_skb failed\n");
        return NULL;
    }

   
    uint16_t id = ntohs(icmp_in->un.echo.id);
    struct transfer_header* header = (struct transfer_header*)&id;
    
    skb_reserve(skb, hh_len);
    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);
    skb_put(skb, packet_size);
    skb_reset_network_header(skb);
    skb_set_transport_header(skb, sizeof(struct iphdr));
    
    struct iphdr* ip_out = ip_hdr(skb);
    ip_out->version = 4;
    ip_out->ihl = 5;
    ip_out->tos = 0;
    ip_out->tot_len = htons(packet_size - sizeof(struct ethhdr));
    ip_out->id = 0;
    ip_out->frag_off = htons(0x4000);
    ip_out->ttl = 64;
    ip_out->protocol = (header->type == 0)?IPPROTO_UDP:IPPROTO_TCP;
    ip_out->saddr = ip_in->saddr;
    ip_out->daddr = ip_in->daddr;
    ip_out->check = 0;
    ip_out->check = ip_fast_csum((u8 *)ip_out, ip_out->ihl);

    uint8_t* addr_transport_header;
    if (header->type == 0) 
    {
        addr_transport_header = (uint8_t*)udp_hdr(skb);
        
    } 
    else 
    {  
        addr_transport_header = (uint8_t*)tcp_hdr(skb);
    }

    struct list_data* cur = end;
    int cp_size = size;
    while (cur)
    {
        cp_size -= cur->size;
        memcpy (addr_transport_header + cp_size, cur->data, cur->size);
        cur = cur->prev;
    }

    if (header->type == 0) 
    {
        transport_header_len = sizeof(struct udphdr);
        struct udphdr* udph = udp_hdr(skb);
        udph->check = 0;
        pr_info ("in packet1 %u %d : %*ph\n",(uint8_t*)udph,addr_transport_header -  (uint8_t*)udph,size, (uint8_t*)udph);
    } 
    else 
    {  
        struct tcphdr* tcph = tcp_hdr(skb);
        struct tcphdr* tcp_in = (struct tcphdr*)data_in;
        transport_header_len = __tcp_hdrlen(tcp_in);
        tcph->check = 0;
                
        tcph->check = tcp_v4_check(size, 
                                    ip_out->saddr, 
                                    ip_out->daddr, 
                                    csum_partial((char *)tcph, size, 0));
        skb->ip_summed = CHECKSUM_NONE;
    }
    
    
    skb_push(skb, sizeof(struct ethhdr));
    skb_reset_mac_header(skb);
    
    struct ethhdr *eth_out = eth_hdr(skb);
    memset(eth_out, 0, sizeof(struct ethhdr));
    memcpy(eth_out->h_source, mac_in, ETH_ALEN);
    memcpy(eth_out->h_dest, dev->dev_addr, ETH_ALEN);
    eth_out->h_proto = htons(ETH_P_IP);
    return skb;
}

static unsigned int input_hook (void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;

    struct icmphdr *icmph = icmp_hdr(skb);
   
    if (icmph->type != ICMP_ECHOREPLY)
        return NF_ACCEPT;
    
    if (skb_linearize(skb)) 
    {
        pr_info("Failed to linearize skb\n");
        return NULL;
    }    

    static int flag_error = 0;
    static int id_packet = 0;
    static int current_frag = 0;
    static struct list_data* end = NULL;
    static int total_size = 0;
    
    uint16_t id = ntohs(icmph->un.echo.id);
    struct transfer_header* header = (struct transfer_header*)&id;
    pr_info ("in packet %d %d\n",flag_error, ntohs(icmph->un.echo.sequence));
    if (ntohs(icmph->un.echo.sequence) == 0)
    {
        id_packet = header->id;
        flag_error = 0;
        clear_list (&end);
        current_frag = ntohs(icmph->un.echo.sequence);
        total_size = 0;
    }

    if (flag_error == 1)
    {
        return NF_STOLEN;
    }
    if (current_frag == ntohs(icmph->un.echo.sequence)
        && id_packet == header->id)
    {
        current_frag++;
        if (end)
        {
            end->next = kmalloc(sizeof(struct list_data), GFP_ATOMIC);
            if (!end->next)
            {
                flag_error = 1;
                return NF_STOLEN;
            }
            struct list_data* cur = end;
            end = end->next;
            end->prev = cur;
            
        }
        else
        {
            end = kmalloc(sizeof(struct list_data), GFP_ATOMIC);
            if (!end)
            {
                flag_error = 1;
                return NF_STOLEN;
            }
            end->prev = NULL;
            end->next = NULL;
        }
        end->size = (uint8_t*)skb_tail_pointer(skb) - (uint8_t*)icmph - sizeof(struct icmphdr);
        end->data = kmalloc(end->size, GFP_ATOMIC);
        if (!end->data)
        {
            flag_error = 1;
            return NF_STOLEN;
        }
        memcpy(end->data, (uint8_t*)(icmph + 1), end->size);
        total_size += end->size;
    }
    else
    {
        flag_error = 1;
        clear_list (&end);
    }

    if (header->type != 0 && header->type != 1) 
    {
        flag_error = 1;
        clear_list (&end);
        pr_err("Unknown protocol type: %d\n", header->type);
        return NF_STOLEN;
    }

    if (header->last == 1 && flag_error == 0)
    {
        pr_info ("get packet %d %d\n",header->type, total_size);
        struct sk_buff* skb_out = create_packet_input (skb, end, total_size);
        if (!skb_out)
        {
            flag_error = 1;
            clear_list (&end);
            pr_info ("clear_list %u\n",end);
            return NF_STOLEN;
        }
        struct task_data *data = kmalloc(sizeof(struct task_data), GFP_ATOMIC);
        if (!data)
        {
            pr_err("kmalloc\n");
            kfree_skb(skb_out);
            return NF_ACCEPT;
        }

        data->skb = skb_out;
        tasklet_init(&data->tasklet, send_func, (unsigned long)data);
        tasklet_schedule(&data->tasklet);    
    }
    return NF_STOLEN;    
}

static struct sk_buff* create_packet_output(struct sk_buff* in_packet)
{    
    struct iphdr* ip_in = ip_hdr(in_packet);
    uint8_t mac_out[ETH_ALEN];
    uint8_t protocol_type;
    uint16_t data_len;
    uint8_t* data_in;
    
    if (ip_in->protocol != IPPROTO_UDP /*&& ip_in->protocol != IPPROTO_TCP*/) 
    {
        return NULL;
    }
    
    if (find_mac_addr(mac_out, ip_in->daddr, in_packet->dev) < 0) 
    {
        pr_info("Not found mac\n");
        return NULL;
    }
    
    if (skb_linearize(in_packet)) 
    {
        pr_info("Failed to linearize skb\n");
        return NULL;
    }
    
    if (ip_in->protocol == IPPROTO_UDP) 
    {
        struct udphdr* in_udp = udp_hdr(in_packet);
        protocol_type = 0;  
        data_in = (uint8_t*)in_udp;
        data_len = ntohs(in_udp->len);
    } 
    else 
    { 
        struct tcphdr* in_tcp = tcp_hdr(in_packet);
        protocol_type = 1;  
        data_in = (uint8_t*)in_tcp;
        data_len =  ntohs(ip_in->tot_len) - (ip_in->ihl * 4);
    }
    pr_info ("out packet %*ph\n",data_len, data_in);
    static uint8_t id = 0;
    id++;
    
    int hh_len = LL_RESERVED_SPACE(in_packet->dev);
    int tlen = in_packet->dev->needed_tailroom;
    static const int max_size = 10;
    struct sk_buff* skb_out = NULL;
    struct sk_buff* skb_current = NULL;
    uint16_t frag = 0;
    pr_info ("start create_packet_output %d\n",data_len);
    while(true)
    {
        int packet_len = (data_len>max_size)?max_size:data_len;
        data_len -= packet_len;

        int packet_size = sizeof(struct ethhdr) 
                    + sizeof(struct iphdr) 
                    + sizeof(struct icmphdr)
                    + packet_len;

        struct sk_buff* skb = netdev_alloc_skb(in_packet->dev, hh_len + tlen + packet_size);
        
        if (!skb) 
        {
            while (skb_out)
            {
                skb = skb_out->next;
                kfree_skb(skb_out);
                skb_out = skb;
            }
            pr_err("netdev_alloc_skb failed\n");
            return NULL;
        }

        if (!skb_out)
        {
            skb_out = skb;
        }

        if (skb_current)
        {
            skb_current->next = skb;
            skb->prev = skb_current;
        }
        
        skb_reserve(skb, hh_len);
        skb->dev = in_packet->dev;
        skb->protocol = htons(ETH_P_IP);
        skb_put(skb, packet_size);
        skb_reset_network_header(skb);
        skb_set_transport_header(skb, sizeof(struct iphdr));
        
        struct iphdr* ip_out = ip_hdr(skb);
        ip_out->version = 4;
        ip_out->ihl = 5;
        ip_out->tos = 0;
        ip_out->tot_len = htons(packet_size - sizeof(struct ethhdr));
        ip_out->id = 0;
        ip_out->frag_off = htons(0x4000);
        ip_out->ttl = 64;
        ip_out->protocol = IPPROTO_ICMP;
        ip_out->saddr = ip_in->saddr;
        ip_out->daddr = ip_in->daddr;
        ip_out->check = 0;
        ip_out->check = ip_fast_csum((u8 *)ip_out, ip_out->ihl);
        
        struct transfer_header header;
        header.id = id;
        header.last = (data_len == 0)?1:0;
        header.type = protocol_type;
        header.reserv = 0;
        
        struct icmphdr* icmp = icmp_hdr(skb);
        icmp->type = ICMP_ECHOREPLY;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->un.echo.id = htons(*(uint16_t*)&header);
        icmp->un.echo.sequence = htons(frag++);
        
        uint8_t* data_out = (uint8_t*)(icmp + 1);
        memcpy(data_out, data_in, packet_len);
        
        icmp->checksum = ip_compute_csum(icmp, sizeof(struct icmphdr) + packet_len);
        
        skb_push(skb, sizeof(struct ethhdr));
        skb_reset_mac_header(skb);
        
        struct ethhdr *eth_out = eth_hdr(skb);
        memset(eth_out, 0, sizeof(struct ethhdr));
        memcpy(eth_out->h_source, skb->dev->dev_addr, ETH_ALEN);
        memcpy(eth_out->h_dest, mac_out, ETH_ALEN);
        eth_out->h_proto = htons(0x0800);

        skb_current = skb;
        data_in += packet_len;
        pr_info ("out add frag %d %d %u %d %d\n",frag, packet_len, (uint32_t)skb_current,icmp->un.echo.id,icmp->un.echo.sequence);
        if (data_len == 0)
            break;
    }
    pr_info ("end create_packet_output %d\n",frag);
    skb_current = skb_out;

    
    return skb_out;
}

static unsigned int output_hook (void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct sk_buff *skb_out = create_packet_output (skb);
    if (!skb_out)
        return NF_ACCEPT;
    struct sk_buff* skb_current = skb_out;
    while (skb_current)
    {
        skb_current = skb_current->next;
    }
    struct task_data *data = kmalloc(sizeof(struct task_data), GFP_ATOMIC);
    if (!data)
    {
        pr_err("kmalloc\n");
        kfree_skb(skb_out);
        return NF_ACCEPT;
    }
    data->skb = skb_out;
    tasklet_init(&data->tasklet, send_func, (unsigned long)data);
    tasklet_schedule(&data->tasklet);
    return NF_STOLEN;
}

static int __init init (void) 
{
    inputHook.hook = input_hook;
    inputHook.hooknum = NF_INET_LOCAL_IN;
    inputHook.pf = PF_INET;
    inputHook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &inputHook);

    outputHook.hook = output_hook;
    outputHook.hooknum = NF_INET_POST_ROUTING;
    outputHook.pf = PF_INET;
    outputHook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &outputHook);

    printk(KERN_INFO "Hello, World!\n");
    return 0;
}

static void __exit exit (void) 
{
    nf_unregister_net_hook(&init_net, &inputHook);
    nf_unregister_net_hook(&init_net, &outputHook);
    printk(KERN_INFO "Goodbye, World!\n");
}

module_init(init);
module_exit(exit);