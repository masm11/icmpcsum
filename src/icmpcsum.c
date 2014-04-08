/* icmpcsum - adjusting filter of icmp checksum
 * Copyright (C) 2007 Yuuki Harano
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <time.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define ADDR_REFRESH_TIME	3600

static uint32_t addr_i, addr_o;

static int log_to_syslog = 0;
static void log_printf(int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (log_to_syslog)
	vsyslog(level, fmt, ap);
    else {
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
    }
    va_end(ap);
}

static uint16_t calcsum(unsigned char *ptr, int size)
{
    uint32_t sum = 0;
    
    while (size >= 2) {
	sum += *(uint16_t *) ptr;
	ptr += 2;
	size -= 2;
    }
    if (size >= 1)
	sum += *ptr;
    
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static int work(unsigned char *data, int size)
{
    struct iphdr *iph = (struct iphdr *) data;
    
    // ip header その他を確認。
    
    if (iph->version != 4)
	return 0;
    
    if (ntohs(iph->frag_off) >= 0x2000)
	return 0;
    
    if (size < ntohs(iph->tot_len))
	return 0;
    
    if (size < iph->ihl * 4)
	return 0;
    
    if (calcsum((unsigned char *) iph, iph->ihl * 4) != 0)
	return 0;
    
    // icmp 以外は無関係。
    if (iph->protocol != IPPROTO_ICMP)
	return 0;
    
    struct icmp *icp = (struct icmp *) ((uint32_t *) iph + iph->ihl);
    
    /* CTU から返ってきたパケットは checksum が正しい。
     * CTU につないだ他の機器から返ってきたものも当然正しいだろう。
     * そういったチェックをするのは面倒なので、
     * iptables の rule の方で弾くことにする。
     * 
     * 「icmp 以外は無関係」… これは、最低限チェックしないと、
     * icmp として扱えない。例えば、iptables の設定を間違えると、
     * TCP のパケットがやって来て、それをいじってしまうかもしれない。
     * それは絶対避けねば。
     * でも、icmp であることが判れば、いくらか気が楽。
     */
#if 0
    if (calcsum((unsigned char *) icp, ntohs(iph->tot_len) - iph->ihl * 4) == 0)
	return 0;
#endif
    
    /* echo reply はいつも正しい */
    if (icp->icmp_type == ICMP_ECHOREPLY)
	return 0;
    
    /* checksum を直す。*/
    
    uint16_t icmp_oldsum = icp->icmp_cksum;
    
    uint32_t sum = icmp_oldsum;
    sum += addr_i >> 16;
    sum += addr_i & 0xffff;
    sum -= addr_o >> 16;
    sum -= addr_o & 0xffff;
    sum += addr_i >> 16;
    sum += addr_i & 0xffff;
    sum -= addr_o >> 16;
    sum -= addr_o & 0xffff;
    sum = (sum & 0xffff) + ((int32_t) sum >> 16);
    sum = (sum & 0xffff) + ((int32_t) sum >> 16);
    
    icp->icmp_cksum = sum;
    
    log_printf(LOG_WARNING, "checksum adjusted: %04x=>%04x.", icmp_oldsum, sum);
    
    return 1;
}

static int handle(struct nfq_q_handle *gh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfad, void *closure)
{
    struct nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(nfad);
    if (hdr == 0)
	return -1;
    
    u_int32_t id = ntohl(hdr->packet_id);
    
    char *data;
    int size = nfq_get_payload(nfad, &data);
    if (size < 0)
	return size;
    
    if (!work((unsigned char *) data, size))
	return nfq_set_verdict(gh, id, NF_ACCEPT, 0, NULL);
    else
	return nfq_set_verdict(gh, id, NF_ACCEPT, size, (unsigned char *) data);
    
    return 0;
}

static uint32_t get_addr(const char *cmd)
{
    uint32_t addr = 0xffffffff;
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
	log_printf(LOG_WARNING, "can't exec cmd: %s", cmd);
	goto done;
    }
    
    char buf[128];
    if (fgets(buf, sizeof buf, fp) == NULL) {
	log_printf(LOG_WARNING, "read from cmd failed %s", cmd);
	goto done;
    }
    char *p;
    if ((p = strchr(buf, '\n')) == NULL) {
	log_printf(LOG_WARNING, "line from cmd too long %s", cmd);
	goto done;
    }
    
    addr = inet_addr(buf);
    if (addr == 0xffffffff) {
	log_printf(LOG_WARNING, "bad addr from cmd %s", cmd);
	goto done;
    }
    
 done:
    if (fp != NULL)
	fclose(fp);
    return addr;
}

int main(int argc, char **argv)
{
    const char *cmd_i = NULL;
    const char *cmd_o = NULL;
    int queue_num = 0;
    
    argv++;
    argc--;
    
    while (argc >= 1) {
	if (argc >= 2 && strcmp(argv[0], "-q") == 0) {
	    char *ep;
	    queue_num = strtol(argv[1], &ep, 0);
	    if (*ep != '\0') {
		log_printf(LOG_ERR, "bad queue num.");
		exit(1);
	    }
	    
	    argv += 2;
	    argc -= 2;
	} else if (argc >= 2 && strcmp(argv[0], "-i") == 0) {
	    cmd_i = argv[1];
	    
	    argv += 2;
	    argc -= 2;
	} else if (argc >= 2 && strcmp(argv[0], "-o") == 0) {
	    cmd_o = argv[1];
	    
	    argv += 2;
	    argc -= 2;
	} else {
	    log_printf(LOG_INFO, "usage: icmpcsum [-q <queue_num>] -i <cmd> -o <cmd>");
	    exit(1);
	}
    }
    
    if (cmd_i == NULL) {
	log_printf(LOG_ERR, "-i not specified.");
	exit(1);
    }
    if (cmd_o == NULL) {
	log_printf(LOG_ERR, "-o not specified.");
	exit(1);
    }
    
    addr_i = get_addr(cmd_i);
    if (addr_i == 0xffffffff)
	exit(1);
    
    addr_o = get_addr(cmd_o);
    if (addr_o == 0xffffffff)
	exit(1);
    
    struct timespec nexttime;
    if (clock_gettime(CLOCK_MONOTONIC, &nexttime) == -1) {
	log_printf(LOG_ERR, "clock_gettime() failed.");
	exit(1);
    }
    nexttime.tv_sec += ADDR_REFRESH_TIME;
    
    struct nfq_handle *h = nfq_open();
    if (h == NULL) {
	log_printf(LOG_ERR, "nfq_open() failed.");
	exit(1);
    }
    
    int r;
    if ((r = nfq_bind_pf(h, PF_INET)) < 0) {
	if (r != -EEXIST) {
	    log_printf(LOG_ERR, "nfq_bind_pf() failed.");
	    exit(1);
	}
	// 既に nf_queue に向いてる。
	// NFNETLINK answers: File exists なんて言われるが、気にしない。
    }
    
    struct nfq_q_handle *qh = nfq_create_queue(h, queue_num, handle, NULL);
    if (qh == NULL) {
	log_printf(LOG_ERR, "nfq_create_queue() failed.");
	exit(1);
    }
    
    if ((r = nfq_set_mode(qh, NFQNL_COPY_PACKET, 65535)) < 0) {
	log_printf(LOG_ERR, "nfq_set_mode() failed.");
	exit(1);
    }
    
    if (daemon(0, 0) == 01) {
	log_printf(LOG_ERR, "daemonize failed.");
	exit(1);
    }
    
    openlog("icmpcsum", LOG_NDELAY | LOG_PID, LOG_DAEMON);
    log_to_syslog = 1;
    
    log_printf(LOG_INFO, "started.");
    
    log_printf(LOG_INFO, "addr_i: %s", inet_ntoa((struct in_addr) { .s_addr = addr_i, }));
    log_printf(LOG_INFO, "addr_o: %s", inet_ntoa((struct in_addr) { .s_addr = addr_o, }));

    int fd = nfq_fd(h);
    while (1) {
	struct timespec nowtime;
	if (clock_gettime(CLOCK_MONOTONIC, &nowtime) == -1) {
	    log_printf(LOG_ERR, "clock_gettime() failed.");
	    exit(1);
	}
	
	int tmo = (nexttime.tv_sec - nowtime.tv_sec) * 1000 + (nexttime.tv_nsec - nowtime.tv_nsec) / 1000000;
	if (tmo <= 0) {
	    nexttime.tv_sec += ADDR_REFRESH_TIME;
	    
	    uint32_t addr;
	    addr = get_addr(cmd_i);
	    if (addr != 0xffffffff) {
		addr_i = addr;
		log_printf(LOG_INFO, "new addr_i: %s", inet_ntoa((struct in_addr) { .s_addr = addr_i, }));
	    }
	    addr = get_addr(cmd_o);
	    if (addr != 0xffffffff) {
		addr_o = addr;
		log_printf(LOG_INFO, "new addr_o: %s", inet_ntoa((struct in_addr) { .s_addr = addr_o, }));
	    }
	    
	    if (clock_gettime(CLOCK_MONOTONIC, &nowtime) == -1) {
		log_printf(LOG_ERR, "clock_gettime() failed.");
		exit(1);
	    }
	    tmo = (nexttime.tv_sec - nowtime.tv_sec) * 1000 + (nexttime.tv_nsec - nowtime.tv_nsec) / 1000000;
	    if (tmo <= 0)
		tmo = 1;
	}
	
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, tmo) > 0) {
	    char buf[102400];
	    ssize_t siz = recv(fd, buf, sizeof buf, 0);
	    if (siz == 0)
		break;
	    if (siz > 0)
		nfq_handle_packet(h, buf, siz);
	    else {
		if (errno != EINTR) {
		    perror("recv");
		    break;
		}
	    }
	}
    }
    
    closelog();
    
    return 0;
}
