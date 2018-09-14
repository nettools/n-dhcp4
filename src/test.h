#pragma once

/*
 * Test Helpers
 * Bunch of helpers to setup the environment for networking tests. This
 * includes net-namespace setups, veth setups, and more.
 */

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static inline void test_set_netns(int netns, int *oldnsp) {
        int r;

        if (oldnsp) {
                *oldnsp = open("/proc/self/ns/net", O_RDONLY);
                assert(*oldnsp >= 0);
        }

        r = setns(netns, CLONE_NEWNET);
        assert(!r);
}

static inline void test_socket_new(int netns, int *sockfdp, int family, int ifindex) {
        char ifname[IF_NAMESIZE];
        char *p;
        int r, sockfd, oldns;

        test_set_netns(netns, &oldns);

        p = if_indextoname(ifindex, ifname);
        assert(p);

        sockfd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        assert(sockfd >= 0);

        r = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
        assert(r >= 0);

        test_set_netns(oldns, NULL);

        *sockfdp = sockfd;
}

static inline void test_add_ip(int netns, int ifindex, const struct in_addr *addr, unsigned int prefix) {
        char ifname[IF_NAMESIZE];
        char *p;
        int r, oldns;

        test_set_netns(netns, &oldns);

        p = if_indextoname(ifindex, ifname);
        assert(p);

        r = asprintf(&p, "ip addr add %s/%u dev %s", inet_ntoa(*addr), prefix, ifname);
        assert(r >= 0);

        r = system(p);
        assert(r == 0);

        test_set_netns(oldns, NULL);

        free(p);
}

static inline void test_del_ip(int netns, int ifindex, const struct in_addr *addr, unsigned int prefix) {
        char ifname[IF_NAMESIZE];
        char *p;
        int r, oldns;

        test_set_netns(netns, &oldns);

        p = if_indextoname(ifindex, ifname);
        assert(p);

        r = asprintf(&p, "ip addr del %s/%u dev %s", inet_ntoa(*addr), prefix, ifname);
        assert(r >= 0);

        r = system(p);
        assert(r == 0);

        test_set_netns(oldns, NULL);

        free(p);
}

static inline void test_if_query(const char *name, int *indexp, struct ether_addr *macp) {
        struct ifreq ifr = {};
        size_t l;
        int r, s;

        l = strlen(name);
        assert(l <= IF_NAMESIZE);

        if (indexp) {
                *indexp = if_nametoindex(name);
                assert(*indexp > 0);
        }

        if (macp) {
                s = socket(AF_INET, SOCK_DGRAM, 0);
                assert(s >= 0);

                strncpy(ifr.ifr_name, name, l + 1);
                r = ioctl(s, SIOCGIFHWADDR, &ifr);
                assert(r >= 0);

                memcpy(macp->ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

                close(s);
        }
}

static inline void test_veth_new(int *parent_nsp,
                                 int *parent_indexp,
                                 struct ether_addr *parent_macp,
                                 int *child_nsp,
                                 int *child_indexp,
                                 struct ether_addr *child_macp) {
        int r, oldns;

        /*
         * Create a new veth pair, with each end in a different network namespace.
         */

        r = system("ip link add veth-parent type veth peer name veth-child");
        assert(r == 0);

        r = system("ip netns add ns-parent");
        assert(r == 0);
        *parent_nsp = open("/run/netns/ns-parent", O_RDONLY);
        assert(*parent_nsp >= 0);

        r = system("ip link set veth-parent up addrgenmode none netns ns-parent");
        assert(r == 0);
        test_set_netns(*parent_nsp, &oldns);
        test_if_query("veth-parent", parent_indexp, parent_macp);
        test_set_netns(oldns, NULL);

        r = system("ip netns del ns-parent");
        assert(r == 0);

        r = system("ip netns add ns-child");
        assert(r == 0);
        *child_nsp = open("/run/netns/ns-child", O_RDONLY);
        assert(*child_nsp >= 0);

        r = system("ip link set veth-child up addrgenmode none netns ns-child");
        assert(r == 0);
        test_set_netns(*child_nsp, &oldns);
        test_if_query("veth-child", child_indexp, child_macp);
        test_set_netns(oldns, NULL);

        r = system("ip netns del ns-child");
        assert(r == 0);
}

static inline int test_setup(void) {
        int r;

        /*
         * Move into a new network and mount namespace, and create
         * a private instance of /run/netns. This ensures that any
         * network devices or network namespaces are private to the
         * test process.
         */

        r = unshare(CLONE_NEWNET | CLONE_NEWNS);
        if (r < 0) {
                assert(errno == EPERM);
                return 77;
        }

        r = mount(NULL, "/run", NULL, MS_PRIVATE, NULL);
        assert(r >= 0);

        r = mkdir("/run/netns", 0755);
        if (r < 0)
                assert(errno == EEXIST);

        r = mount(NULL, "/run/netns", "tmpfs", 0, NULL);
        assert(r >= 0);

        return 0;
}
