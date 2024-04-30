#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <skbuff.h>

/*
inspired by Chris Bao's blog post
https://organicprogrammer.com/2022/06/08/how-to-write-a-netfilter-firewall-part3/
and Oracle's Introduction to Netfilter
https://blogs.oracle.com/linux/post/introduction-to-netfilter#:~:text=priority%20%2D%20The%20priority%20of%20the,passed%20to%20the%20hook%20function.


instructions:
- compile with `make`
- load the kernel module with `insmod firewall.ko`
- remove the module with `rmmod firewall`
*/

static struct nf_hook_ops *nf_block_icmp_pkt_ops = NULL;

static unsigned int nf_block_icmp_pkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;

	if (!skb)
	{
		pr_info("fw_info No skb\n");
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_ICMP)
	{
		pr_info("fw_info Droping ICMP Packet\n");
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static int __init firewall_init(void)
{
	pr_info("Starting firewall\n");
	nf_block_icmp_pkt_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	if (nf_block_icmp_pkt_ops != NULL)
	{
		nf_block_icmp_pkt_ops->hook = (nf_hookfn *)nf_block_icmp_pkt_handler;
		nf_block_icmp_pkt_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_block_icmp_pkt_ops->pf = NFPROTO_IPV4;
		nf_block_icmp_pkt_ops->priority = NF_IP_PRI_FIRST;

		nf_register_net_hook(&init_net, nf_block_icmp_pkt_ops);
	}
	return 0;
}

static void __exit firewall_exit(void)
{
	if (nf_block_icmp_pkt_ops != NULL)
	{
		nf_unregister_net_hook(&init_net, nf_block_icmp_pkt_ops);
		kfree(nf_block_icmp_pkt_ops);
	}
	pr_info(KERN_INFO "Exiting firewall\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");