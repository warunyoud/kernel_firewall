#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/inet.h>

static struct nf_hook_ops nfho1;

unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;
  unsigned char *iter;
  unsigned char *tail;
  u32 port;

  if (skb == NULL) return NF_ACCEPT;

  // Make sure it is a TCP packet
  iph = ip_hdr(skb);
  if (iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

  tcph = tcp_hdr(skb);
  iter = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
  tail = skb_tail_pointer(skb);

  // Ensuring HTTP port
  port = ntohs(tcph->dest);
  if (port != 80) return NF_ACCEPT;

  // Printing out the packet
  for (;iter != tail; iter++) {
    char output = *(char *) iter;
    if (output == '\0') break;
    printk(KERN_CONT "%c", output);
  }
  return NF_ACCEPT;
}


int init_module()
{
  nfho1.hook = hook_func_out;
  nfho1.hooknum = NF_INET_POST_ROUTING;
  nfho1.pf = PF_INET;
  nfho1.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(&init_net, &nfho1);
  printk(KERN_INFO "http_sniffer loaded\n");
  return 0;
}

void cleanup_module()
{
  printk("http_sniffer unloaded\n");
  nf_unregister_net_hook(&init_net, &nfho1);
}

