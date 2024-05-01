#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

/*
inspired by Chris Bao's blog post
https://organicprogrammer.com/2022/06/08/how-to-write-a-netfilter-firewall-part3/
and Oracle's Introduction to Netfilter
https://blogs.oracle.com/linux/post/introduction-to-netfilter#:~:text=priority%20%2D%20The%20priority%20of%20the,passed%20to%20the%20hook%20function.

https://tldp.org/LDP/lkmpg/2.6/html/x121.html
https://linux-kernel-labs..io/refs/heads/master/labs/networking.html


instructions:
- compile with `make`
- load the kernel module with `sudo insmod firewall.ko`
- see the kernel module with `lsmod`
- remove the module with `sudo rmmod firewall`
*/

static unsigned int nf_block_icmp_packet_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *ip_header;

	if (!skb)
	{
		return NF_ACCEPT;
	}

	ip_header = ip_hdr(skb);
	if (ip_header->protocol == IPPROTO_ICMP)
	{
		pr_info("Dropping ICMP packet");
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops *nf_block_icmp_packet_options = NULL;
static int __init firewall_init(void)
{
	nf_block_icmp_packet_options = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	if (nf_block_icmp_packet_options == NULL)
	{
		return 0;
	}

	nf_block_icmp_packet_options->hook = (nf_hookfn *)nf_block_icmp_packet_handler;
	nf_block_icmp_packet_options->hooknum = NF_INET_PRE_ROUTING;
	nf_block_icmp_packet_options->pf = NFPROTO_IPV4;
	nf_block_icmp_packet_options->priority = NF_IP_PRI_FIRST; // set the priority

	nf_register_net_hook(&init_net, nf_block_icmp_packet_options);
	return 0;
}

static void __exit firewall_exit(void)
{
	printk(KERN_INFO "Exit");

	if (nf_block_icmp_packet_options == NULL)
	{
		return;
	}

	nf_unregister_net_hook(&init_net, nf_block_icmp_packet_options);
	kfree(nf_block_icmp_packet_options);
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
