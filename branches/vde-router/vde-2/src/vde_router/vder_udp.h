#include "vde_headers.h"
#include "vde_router.h"
#include "vder_queue.h"
#include "vder_datalink.h"
#include "vder_packet.h"
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifndef __VDER_UDP_H
#define __VDER_UDP_H


struct vder_udp_socket {
	struct vder_udp_socket *next;
	uint16_t port;
	struct vder_queue inq;
};

#define UDPSOCK_BUFFER_SIZE 1024 * 16

struct vder_udp_socket *get_by_port(uint16_t port);


/* interface toward the router */
int vder_udp_recv(struct vde_buff *buf);
struct vder_udp_socket *vder_udpsocket_open(uint16_t port);
void vder_udp_close(struct vder_udp_socket *sock);
int vder_udpsocket_sendto(struct vder_udp_socket *sock, void *data, size_t len, uint32_t dst, uint16_t dstport);
int vder_udpsocket_recvfrom(struct vder_udp_socket *sock, void *data, size_t len, uint32_t *from, uint16_t *fromport);

#endif
