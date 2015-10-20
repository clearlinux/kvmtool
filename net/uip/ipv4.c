#include "kvm/uip.h"

int uip_tx_do_ipv4(struct uip_tx_arg *arg)
{
	struct uip_ip *ip;

	ip = (struct uip_ip *)(arg->eth);

	switch (ip->proto) {
	case UIP_IP_P_ICMP:
		uip_tx_do_ipv4_icmp(arg);
		break;
	case UIP_IP_P_TCP:
		uip_tx_do_ipv4_tcp(arg);
		break;
	case UIP_IP_P_UDP:
		uip_tx_do_ipv4_udp(arg);
		break;
	default:
		break;
	}

	return 0;
}
