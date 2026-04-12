#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/arp.h>


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
    if (dev_queue_xmit(data->skb) != 0) 
    {
        pr_err("dev_queue_xmit failed\n");
        kfree_skb(data->skb);
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

static struct sk_buff* create_packet_input (struct sk_buff* in_packet)
{    
    struct iphdr* ip_in = ip_hdr(in_packet);

    struct net_device *dev = dev_get_by_name(&init_net, "lo");
    if (!dev)
     {
        pr_err("Cannot get device\n");
        return NULL;
    }
    
    uint8_t mac_in[ETH_ALEN];
    if (find_mac_addr (mac_in, ip_in->saddr, in_packet->dev) < 0)
    {
        pr_info("Not faund mac\n");
        return NULL;
    }  

    struct icmphdr* icmp_in = icmp_hdr(in_packet);


    uint16_t data_len = (uint8_t*)skb_tail_pointer(in_packet) 
                        - (uint8_t*)icmp_in 
                        - sizeof(struct icmphdr)
                        - sizeof(struct udphdr);
    int packet_size = sizeof(struct ethhdr) 
                    + sizeof(struct iphdr) 
                    + sizeof(struct udphdr)
                    + data_len;
    
    pr_info("create_packet_input %d\n",data_len);
    //return NULL;
    int hh_len = LL_RESERVED_SPACE(dev);
    int tlen = dev->needed_tailroom;
    struct sk_buff* skb = netdev_alloc_skb(dev, hh_len + tlen + packet_size);
    if (unlikely(!skb)) 
    {
        pr_err("netdev_alloc_skb failed\n");
        return NULL;
    }

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
    ip_out->protocol = IPPROTO_UDP;
    ip_out->saddr = ip_in->saddr;
    ip_out->daddr = ip_in->daddr;
    ip_out->check = 0;
    ip_out->check = ip_fast_csum((u8 *)ip_out, ip_out->ihl);
  
    uint8_t* data_in = (uint8_t*)(icmp_in + 1);
    struct udphdr* udph_in = (struct udphdr*)data_in;
    struct udphdr* udph = udp_hdr(skb);
    udph->source = htons(4020);//udph_in->dest;
    udph->dest = htons(4020);//udph_in->source;
    udph->len = udph_in->len;
    udph->check = 0;
    uint8_t* data_out = (uint8_t*)(udph + 1);
    memcpy (data_out, data_in + sizeof(struct udphdr ), data_len);
    
    skb_push(skb, sizeof(struct ethhdr));
    skb_reset_mac_header(skb); 

    struct ethhdr *eth_out = eth_hdr(skb);
    memset (eth_out, 0, sizeof (struct ethhdr));
    memcpy(eth_out->h_source, mac_in, ETH_ALEN);
    memcpy(eth_out->h_dest, dev->dev_addr, ETH_ALEN);
    eth_out->h_proto = htons(0x0800);
    //memcpy(eth_out, eth_in, sizeof (struct ethhdr));
    pr_info("port in %d: %d\n",ntohs(udph->source),ntohs(udph->dest));
    pr_info("icmp: %*ph\n",(uint8_t*)skb_tail_pointer(in_packet) - (uint8_t*)icmp_in, icmp_in);
    pr_info("udp: %*ph\n",sizeof(struct udphdr), udph);
    pr_info("data %d: %*ph\n",data_len,data_len, data_out);
    return skb;
}

static unsigned int input_hook (void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;

    struct icmphdr *icmph = icmp_hdr(skb);
   
    if (icmph->type != ICMP_ECHO)
        return NF_ACCEPT;

    struct sk_buff *skb_out = create_packet_input (skb);
    if (!skb_out)
        return NF_ACCEPT;

    struct task_data *data = kmalloc(sizeof(struct task_data), GFP_ATOMIC);
    if (!data)
    {
        pr_err("kmalloc\n");
        kfree_skb(skb_out);
        return NF_ACCEPT;
    }
    pr_info ("input_hook packet\n");
    data->skb = skb_out;
    tasklet_init(&data->tasklet, send_func, (unsigned long)data);
    tasklet_schedule(&data->tasklet);    
    return NF_STOLEN;    
}

static struct sk_buff* udp_to_icmp (struct sk_buff* in_packet)
{
    struct iphdr* ip_in = ip_hdr(in_packet);
    uint8_t mac_out[ETH_ALEN];
    if (find_mac_addr (mac_out, ip_in->daddr, in_packet->dev) < 0)
    {
        pr_info("Not faund mac\n");
        return NULL;
    }
    struct udphdr* in_udp =  udp_hdr (in_packet);
    if (ntohs(in_udp->dest) != 4020)
        return NULL;
    uint16_t data_len = ntohs(in_udp->len) - sizeof(struct udphdr);
    int packet_size = sizeof(struct ethhdr) 
                    + sizeof(struct iphdr) 
                    + sizeof(struct icmphdr)
                    + sizeof(struct udphdr)
                    + data_len;
    

    //return NULL;
    int hh_len = LL_RESERVED_SPACE(in_packet->dev);
    int tlen = in_packet->dev->needed_tailroom;
    struct sk_buff* skb = netdev_alloc_skb(in_packet->dev, hh_len + tlen + packet_size);
    if (unlikely(!skb)) 
    {
        pr_err("netdev_alloc_skb failed\n");
        return NULL;
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
    static uint8_t id = 0;
    header.id = id++;
    header.last = 1;
    header.type = 0;
    
    struct icmphdr* icmp = icmp_hdr(skb);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = htons(*(uint16_t*)&header);
    icmp->un.echo.sequence = 1;

    uint8_t* data_out = (uint8_t*)(icmp + 1);
    memcpy (data_out, in_udp, sizeof (struct udphdr));
    data_out += sizeof (struct udphdr);
    memcpy (data_out, (uint8_t*)(in_udp + 1), data_len);
    icmp->checksum = ip_compute_csum(icmp, sizeof(struct icmphdr) 
                                            + sizeof(struct udphdr)
                                            + data_len);
    
    skb_push(skb, sizeof(struct ethhdr));
    skb_reset_mac_header(skb); 

    struct ethhdr *eth_out = eth_hdr(skb);
    memset (eth_out, 0, sizeof (struct ethhdr));
    memcpy(eth_out->h_source, skb->dev->dev_addr, ETH_ALEN);
    memcpy(eth_out->h_dest, mac_out, ETH_ALEN);
    eth_out->h_proto = htons(0x0800);
    pr_info("out %d: %*ph\n",data_len,data_len, data_out);
    return skb;
}

static struct sk_buff* create_packet_output (struct sk_buff* in_packet)
{    
    
    struct iphdr *ip = ip_hdr(in_packet);

    if (ip->protocol == IPPROTO_UDP)
    {
        return udp_to_icmp (in_packet);
    }
    else
    {
        pr_err("create_icmp_packet invalid proto %d\n",ip->protocol);
        return NULL;
    }
}

static unsigned int output_hook (void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct sk_buff *skb_out = create_packet_output (skb);
    if (!skb_out)
        return NF_ACCEPT;
    
    struct task_data *data = kmalloc(sizeof(struct task_data), GFP_ATOMIC);
    if (!data)
    {
        pr_err("kmalloc\n");
        kfree_skb(skb_out);
        return NF_ACCEPT;
    }
    pr_info ("start icmp packet\n");
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