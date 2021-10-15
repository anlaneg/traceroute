/*
    Copyright (c)  2006, 2007		Dmitry Butskoy
					<buc@citadel.stu.neva.ru>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include "traceroute.h"


#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE	136
#endif

#ifndef UDPLITE_SEND_CSCOV
#define UDPLITE_SEND_CSCOV	10
#define UDPLITE_RECV_CSCOV	11
#endif


static sockaddr_any dest_addr = {{ 0, }, };
static unsigned int curr_port = 0;
static unsigned int protocol = IPPROTO_UDP;

/*指向申请的报文负载*/
static char *data = NULL;
static size_t *length_p;/*报文长度*/

static void fill_data (size_t *packet_len_p) {
	int i;

	length_p = packet_len_p;

	if (*length_p &&
	    !(data = malloc (*length_p))
	)  error ("malloc");

	/*填充报文0x40,0x41,0x42....*/
        for (i = 0; i < *length_p; i++)
                data[i] = 0x40 + (i & 0x3f);
 
	return;
}

/*初始化port及报文负载*/
static int udp_default_init (const sockaddr_any *dest,
				unsigned int port_seq, size_t *packet_len_p) {

    /*未指供port_seq时，以DEF_START_PORT为准*/
	curr_port = port_seq ? port_seq : DEF_START_PORT;

	dest_addr = *dest;
	dest_addr.sin.sin_port = htons (curr_port);

	fill_data (packet_len_p);

	return 0;
}


static int udp_init (const sockaddr_any *dest,
			    unsigned int port_seq, size_t *packet_len_p) {

	dest_addr = *dest;

	if (!port_seq)  port_seq = DEF_UDP_PORT;
	dest_addr.sin.sin_port = htons ((uint16_t) port_seq);
	
	fill_data (packet_len_p);
 
	return 0;
}


static unsigned int coverage = 0;
#define MIN_COVERAGE	(sizeof (struct udphdr))

static void set_coverage (int sk) {
	int val = MIN_COVERAGE;

	if (setsockopt (sk, IPPROTO_UDPLITE, UDPLITE_SEND_CSCOV,
					    &coverage, sizeof (coverage)) < 0
	)  error ("UDPLITE_SEND_CSCOV");

	if (setsockopt (sk, IPPROTO_UDPLITE, UDPLITE_RECV_CSCOV,
					    &val, sizeof (val)) < 0
	)  error ("UDPLITE_RECV_CSCOV");
}
	
static CLIF_option udplite_options[] = {
	{ 0, "coverage", "NUM", "Set udplite send coverage to %s (default is "
				_TEXT(MIN_COVERAGE) ")",
				CLIF_set_uint, &coverage, 0, CLIF_ABBREV },
	CLIF_END_OPTION
};

static int udplite_init (const sockaddr_any *dest,
			    unsigned int port_seq, size_t *packet_len_p) {

	dest_addr = *dest;

	if (!port_seq)  port_seq = DEF_UDP_PORT;    /*  XXX: Hmmm...   */
	dest_addr.sin.sin_port = htons ((uint16_t) port_seq);

	protocol = IPPROTO_UDPLITE;

	if (!coverage)  coverage = MIN_COVERAGE;
	
	fill_data (packet_len_p);
 
	return 0;
}

/*udp发送探测报文*/
static void udp_send_probe (probe *pb, int ttl) {
	int sk;
	int af = dest_addr.sa.sa_family;

	/*创建socket*/
	sk = socket (af, SOCK_DGRAM, protocol);
	if (sk < 0)  error ("socket");

	tune_socket (sk);	/*  common stuff   */

	if (coverage)  set_coverage (sk);	/*  udplite case   */

	/*设置ttl*/
	set_ttl (sk, ttl);

	if (connect (sk, &dest_addr.sa, sizeof (dest_addr)) < 0)
		error ("connect");

	use_recverr (sk);


	pb->send_time = get_time ();

	/*发送报文负载*/
	if (do_send (sk, data/*报文负载*/, *length_p/*报文长度*/, NULL) < 0) {
	    close (sk);
	    pb->send_time = 0;
	    return;
	}


	pb->sk = sk;

	/*将socket加入到poll中，等待事件触发*/
	add_poll (sk, POLLIN | POLLERR);

	/*将端口号赋给seq*/
	pb->seq = dest_addr.sin.sin_port;

	/*增加port序号*/
	if (curr_port) {	/*  traditional udp method   */
	    curr_port++;
	    dest_addr.sin.sin_port = htons (curr_port);	/* both ipv4 and ipv6 */
	}

	return;
}


static probe *udp_check_reply (int sk, int err, sockaddr_any *from,
						    char *buf, size_t len) {
	probe *pb;

	pb = probe_by_sk (sk);
	if (!pb)  return NULL;

	if (pb->seq != from->sin.sin_port)
		return NULL;

	if (!err)  pb->final = 1;

	return pb;
}

/*udp探测报文接收*/
static void udp_recv_probe (int sk, int revents) {

	if (!(revents & (POLLIN | POLLERR)))
	    /*仅处理read事件，err事件*/
		return;

	recv_reply (sk, !!(revents & POLLERR)/*是否error*/, udp_check_reply);
}


static void udp_expire_probe (probe *pb) {

	probe_done (pb);
}


/*  All three modules share the same methods except the init...  */

static tr_module default_ops = {
	.name = "default",
	.init = udp_default_init,
	.send_probe = udp_send_probe,
	.recv_probe = udp_recv_probe,
	.expire_probe = udp_expire_probe,
	.header_len = sizeof (struct udphdr),
};

TR_MODULE (default_ops);


static tr_module udp_ops = {
	.name = "udp",
	.init = udp_init,
	.send_probe = udp_send_probe,
	.recv_probe = udp_recv_probe,
	.expire_probe = udp_expire_probe,
	.header_len = sizeof (struct udphdr),
};

TR_MODULE (udp_ops);


static tr_module udplite_ops = {
	.name = "udplite",
	.init = udplite_init,
	.send_probe = udp_send_probe,
	.recv_probe = udp_recv_probe,
	.expire_probe = udp_expire_probe,
	.header_len = sizeof (struct udphdr),
	.options = udplite_options,
};

TR_MODULE (udplite_ops);
