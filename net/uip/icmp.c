#include "kvm/uip.h"

int uip_tx_do_ipv4_icmp(struct uip_tx_arg *arg)
{
	struct uip_ip *ip, *ip2;
	struct uip_icmp *icmp2;
	struct uip_icmp *icmp;
	struct uip_buf *buf;

	ip		= (struct uip_ip *)(arg->eth);
	icmp		= uip_ip_proto(ip);

	/* Check the icmp type first.. */

	switch(icmp->type) {
	case UIP_ICMP_ECHO:
		buf		= uip_buf_clone(arg);
		ip2		= (struct uip_ip *)(buf->eth);
		icmp2		= uip_ip_proto(ip2);
		ip2->sip	= ip->dip;
		ip2->dip	= ip->sip;
		ip2->csum	= 0;
		/*
		 * ICMP reply: 0
		 */
		icmp2->type	= UIP_ICMP_ECHO_REPLY;
		icmp2->csum	= 0;
		ip2->csum	= uip_csum_ip(ip2);
		icmp2->csum	= uip_csum_icmp(ip2, icmp2);

		uip_buf_set_used(arg->info, buf);

		return 0;
	/* FIXME: need to process unreachable reports */
	default:
		return 0;
	}
}
