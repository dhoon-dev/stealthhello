#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <net/ip.h>
#include <net/tcp.h>

#define FRAG_SIZE 150
#define TLS_DEFAULT_PORTNUM 443

struct tlshdr {
	__u8 protocol;
#define TLSPROTO_HANDSHAKE 22
	__u16 version;
	__u16 len;
	/* The protocol messages start here. */
} __attribute__((packed));

struct tls_hs_msghdr {
	__u32 type : 8,
#define TLS_HS_MSGTYPE_CLIENTHELLO 1
		  len : 24;
} __attribute__((packed));

static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	skb_dst_drop(to);
	skb_dst_copy(to, from);
	to->dev = from->dev;
	to->mark = from->mark;

	skb_copy_hash(to, from);

	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
	nf_copy(to, from);
#if IS_ENABLED(CONFIG_IP_VS)
	to->ipvs_property = from->ipvs_property;
#endif
	skb_copy_secmark(to, from);
}

static struct sk_buff *tcp_frag(struct net *net, struct sock *sk, struct sk_buff *from,
		int begin, int end)
{
	struct sk_buff *skb;
	struct iphdr *iph = ip_hdr(from);
	struct tcphdr *tcph = tcp_hdr(from);
	int iph_l, tcph_l, hdr_l, ll_rs, payload_l, len;
	struct rtable *rt = skb_rtable(from);
	__u32 seq;
	__be32 ack_seq;

	iph_l = ip_hdrlen(from);
	tcph_l = tcp_hdrlen(from);
	hdr_l = iph_l + tcph_l;

	payload_l = ntohs(iph->tot_len) - hdr_l;

	seq = ntohl(tcph->seq);
	ack_seq = tcph->ack_seq;

	len = end - begin;
	ll_rs = LL_RESERVED_SPACE(rt->dst.dev);

	skb = alloc_skb(hdr_l + len + ll_rs, GFP_ATOMIC);
	if (!skb)
		return 0;

	ip_copy_metadata(skb, from);
	skb_reserve(skb, ll_rs);
	skb_put(skb, hdr_l + len);
	skb_reset_network_header(skb);
	skb->transport_header = skb->network_header + iph_l;

	if (from->sk)
		skb_set_owner_w(skb, from->sk);

	skb_copy_from_linear_data(from, skb_network_header(skb), hdr_l);
	if (skb_copy_bits(from, hdr_l + begin, skb_transport_header(skb) + tcph_l, len))
		BUG();

	tcph = tcp_hdr(skb);
	tcph->seq = htonl(seq + begin);
	tcph->ack_seq = ack_seq;

	iph = ip_hdr(skb);
	iph->tot_len = htons(hdr_l + len);

	tcph->check = 0;
	skb->csum = csum_partial((unsigned char *)tcph, tcph_l + len, 0);
	tcph->check = tcp_v4_check(
			tcph_l + len,
			iph->saddr,
			iph->daddr,
			skb->csum);
	ip_send_check(iph);
#ifdef DEBUG
	printk("stealthhello: ori.seq: %u, ori.ack_seq: %u, seq: %u, ack_seq: %u\n",
			ntohl(seq), ntohl(ack_seq), ntohl(tcph->seq), ntohl(tcph->ack_seq));
#endif
	return skb;
}

static unsigned int stealth_hello(struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	int tot_l, hdr_l, mtu, ptr;
	struct sk_buff *frag_skb;
	int err;

	if (skb->ip_summed == CHECKSUM_PARTIAL &&
			(err = skb_checksum_help(skb)))
		goto fail;

	mtu = ip_skb_dst_mtu(state->sk, skb);
	if (IPCB(skb)->frag_max_size && IPCB(skb)->frag_max_size < mtu)
		mtu = IPCB(skb)->frag_max_size;

	iph = ip_hdr(skb);
	tot_l = ntohs(iph->tot_len);

	if (mtu <= FRAG_SIZE || tot_l <= FRAG_SIZE)
		goto fail;

	hdr_l = ip_hdrlen(skb) + tcp_hdrlen(skb);

	ptr = FRAG_SIZE - hdr_l;
	frag_skb = tcp_frag(state->net, state->sk, skb, 0, ptr);
	if (!frag_skb)
		goto fail;

	err = state->okfn(state->net, state->sk, frag_skb);
	if (err)
		goto fail;

	IP_INC_STATS(state->net, IPSTATS_MIB_FRAGCREATES);

	frag_skb = tcp_frag(state->net, state->sk, skb, ptr, tot_l - hdr_l);
	if (!frag_skb)
		goto fail;

	err = state->okfn(state->net, state->sk, frag_skb);
	if (err)
		goto fail;

	IP_INC_STATS(state->net, IPSTATS_MIB_FRAGOKS);
	consume_skb(skb);
	return NF_STOLEN;

fail:
	printk("stealthhello: failed\n");
	IP_INC_STATS(state->net, IPSTATS_MIB_FRAGFAILS);
	return NF_ACCEPT;
}

static unsigned int sh_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct tlshdr *tlsh;
	struct tls_hs_msghdr *msgh;
	int iph_l, tot_l, tcph_l, hdr_l, tls_msgs_l;

	iph = ip_hdr(skb);

	if (iph->frag_off & htons(IP_OFFSET | IP_MF))
		return NF_ACCEPT;

	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	
	iph_l = iph->ihl << 2;
	tot_l = ntohs(iph->tot_len);

	tcph = tcp_hdr(skb);
	tcph_l = tcph->doff << 2;

	hdr_l = iph_l + tcph_l + sizeof(struct tlshdr);

	if (ntohs(tcph->dest) != TLS_DEFAULT_PORTNUM || tot_l < hdr_l)
		return NF_ACCEPT;

	tlsh = (struct tlshdr *)((__u8 *)tcph + tcph_l);
	tls_msgs_l = ntohs(tlsh->len);
	if (tot_l < hdr_l + tls_msgs_l)
		return NF_ACCEPT;

	if (tlsh->protocol != TLSPROTO_HANDSHAKE)
		return NF_ACCEPT;

	msgh = (struct tls_hs_msghdr *)((__u8 *)tlsh + sizeof(struct tlshdr));
	while (tls_msgs_l > 0) {
		int msg_l;

		if (msgh->type == TLS_HS_MSGTYPE_CLIENTHELLO) {
#ifdef DEBUG
			printk("stealthhello: %pI4 --> %pI4\n", &iph->saddr, &iph->daddr);
#endif
			return stealth_hello(skb, state);
		}

		msg_l = ntohl(msgh->len << 8);
		tls_msgs_l -= msg_l;
		msgh = (struct tls_hs_msghdr *)((__u8 *)msgh + msg_l);
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops sh = {
	.hook = sh_hook,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_LAST
};

int init_module(void)
{
	return nf_register_net_hook(&init_net, &sh);
}

void cleanup_module(void)
{
	nf_unregister_net_hook(&init_net, &sh);
}

MODULE_LICENSE("GPL");
