/*
 * Test Helpers
 */

#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "test.h"
#include "util/link.h"
#include "util/netns.h"

void test_socket_new(int netns, int *sockfdp, int family, int ifindex) {
        Link l = { .netns = netns, .ifindex = ifindex };

        link_socket(&l, sockfdp, family, SOCK_DGRAM | SOCK_CLOEXEC);
}

void test_add_ip(int netns, int ifindex, const struct in_addr *addr, unsigned int prefix) {
        Link l = { .netns = netns, .ifindex = ifindex };

        link_add_ip4(&l, addr, prefix);
}

void test_del_ip(int netns, int ifindex, const struct in_addr *addr, unsigned int prefix) {
        Link l = { .netns = netns, .ifindex = ifindex };

        link_del_ip4(&l, addr, prefix);
}

void test_veth_new(int parent_ns,
                   int *parent_indexp,
                   struct ether_addr *parent_macp,
                   int child_ns,
                   int *child_indexp,
                   struct ether_addr *child_macp) {
        Link v1, v2;

        link_new_veth(&v1, &v2, parent_ns, child_ns);

        if (parent_indexp)
                *parent_indexp = v1.ifindex;
        if (parent_macp)
                *parent_macp = v1.mac;
        if (child_indexp)
                *child_indexp = v2.ifindex;
        if (child_macp)
                *child_macp = v2.mac;

        link_deinit(&v2);
        link_deinit(&v1);
}
