#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/inet.h>

static struct nf_hook_ops nfho1;
static struct nf_hook_ops nfho2;

unsigned int hook_func_incoming(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  if (!strcmp(state->in->name, "lo"))
    return NF_DROP;
  if (skb == NULL) return NF_ACCEPT;

  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
  if (ip_header == NULL) return NF_ACCEPT;

  if (ip_header->protocol == 6) {
    struct tcphdr *tcp_header = (struct tcphdr *)skb_transport_header(skb);
    unsigned int port = (unsigned int)ntohs(tcp_header->dest);
    if (port == 8888)
      return NF_DROP;
  }
  return NF_ACCEPT;
}

unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  if (skb == NULL) return NF_ACCEPT;

  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
  if (ip_header == NULL) return NF_ACCEPT;

  unsigned int dest_ip = (unsigned int)ip_header->daddr;
  
  if (dest_ip == 0x272eeb67)
    return NF_DROP;
  else
    return NF_ACCEPT;
}


int init_module()
{
  nfho1.hook = hook_func_incoming;
  nfho1.hooknum = NF_INET_PRE_ROUTING; 
  nfho1.pf = PF_INET;
  nfho1.priority = NF_IP_PRI_FIRST;

  nfho2.hook = hook_func_out;
  nfho2.hooknum = NF_INET_POST_ROUTING;
  nfho2.pf = PF_INET;
  nfho2.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(&init_net, &nfho1);
  nf_register_net_hook(&init_net, &nfho2);
  printk(KERN_INFO "custom firewall loaded\n");
  return 0;
}

void cleanup_module()
{
  printk("custom firewall unloaded\n");
  nf_unregister_net_hook(&init_net, &nfho1);
}

