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
#include "util/netns.h"

void test_socket_new(int netns, int *sockfdp, int family, int ifindex) {
        char ifname[IF_NAMESIZE];
        char *p;
        int r, sockfd, oldns;

        netns_get(&oldns);
        netns_set(netns);

        p = if_indextoname(ifindex, ifname);
        assert(p);

        sockfd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        assert(sockfd >= 0);

        netns_set(oldns);

        r = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
        assert(r >= 0);

        *sockfdp = sockfd;
}

void test_add_ip(int netns, int ifindex, const struct in_addr *addr, unsigned int prefix) {
        char ifname[IF_NAMESIZE];
        char *p;
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);

        p = if_indextoname(ifindex, ifname);
        assert(p);

        r = asprintf(&p, "ip addr add %s/%u dev %s", inet_ntoa(*addr), prefix, ifname);
        assert(r >= 0);

        r = system(p);
        assert(r == 0);

        netns_set(oldns);

        free(p);
}

void test_del_ip(int netns, int ifindex, const struct in_addr *addr, unsigned int prefix) {
        char ifname[IF_NAMESIZE];
        char *p;
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);

        p = if_indextoname(ifindex, ifname);
        assert(p);

        r = asprintf(&p, "ip addr del %s/%u dev %s", inet_ntoa(*addr), prefix, ifname);
        assert(r >= 0);

        r = system(p);
        assert(r == 0);

        netns_set(oldns);

        free(p);
}

static void test_if_query(int netns, const char *name, int *indexp, struct ether_addr *macp) {
        struct ifreq ifr = {};
        size_t l;
        int r, s, oldns;

        l = strlen(name);
        assert(l <= IF_NAMESIZE);

        netns_get(&oldns);
        netns_set(netns);

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

        netns_set(oldns);
}

static void test_netns_move_link(int netns, const char *ifname) {
        char *p;
        int r;

        r = asprintf(&p, "ip link set %s up netns ns-test", ifname);
        assert(r > 0);

        netns_pin(netns, "ns-test");
        r = system(p);
        assert(r == 0);
        netns_unpin("ns-test");

        free(p);
}

void test_veth_new(int parent_ns,
                   int *parent_indexp,
                   struct ether_addr *parent_macp,
                   int child_ns,
                   int *child_indexp,
                   struct ether_addr *child_macp) {
        int r, oldns;

        netns_get(&oldns);

        /*
         * Temporarily enter a new network namespace to make sure the
         * interface names are fresh.
         */
        netns_set_anonymous();

        r = system("ip link add veth-parent type veth peer name veth-child");
        assert(r == 0);
        r = system("ip link set veth-parent up addrgenmode none");
        assert(r == 0);
        r = system("ip link set veth-child up addrgenmode none");
        assert(r == 0);

        test_netns_move_link(parent_ns, "veth-parent");
        test_netns_move_link(child_ns, "veth-child");

        netns_set(oldns);

        test_if_query(parent_ns, "veth-parent", parent_indexp, parent_macp);
        test_if_query(child_ns, "veth-child", child_indexp, child_macp);
}

void test_bridge_new(int netns,
                     int *indexp,
                     struct ether_addr *macp) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);
        r = system("ip link add test-bridge type bridge");
        assert(r == 0);
        r = system("ip link set test-bridge up addrgenmode none");
        assert(r == 0);
        netns_set(oldns);

        test_if_query(netns, "test-bridge", indexp, macp);
}

void test_enslave_link(int netns, int master, int slave) {
        char ifname_master[IF_NAMESIZE], ifname_slave[IF_NAMESIZE];
        char *p;
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);

        p = if_indextoname(master, ifname_master);
        assert(p);

        p = if_indextoname(slave, ifname_slave);
        assert(p);

        r = asprintf(&p, "ip link set %s master %s", ifname_slave, ifname_master);
        assert(r > 0);

        r = system(p);
        assert(r == 0);

        netns_set(oldns);

        free(p);
}

static void test_unshare_user_namespace(void) {
        uid_t euid;
        gid_t egid;
        int r, fd;

        /*
         * Enter a new user namespace as root:root.
         */

        euid = geteuid();
        egid = getegid();

        r = unshare(CLONE_NEWUSER);
        assert(r >= 0);

        fd = open("/proc/self/uid_map", O_WRONLY);
        assert(fd >= 0);
        r = dprintf(fd, "0 %d 1\n", euid);
        assert(r >= 0);
        close(fd);

        fd = open("/proc/self/setgroups", O_WRONLY);
        assert(fd >= 0);
        r = dprintf(fd, "deny");
        assert(r >= 0);
        close(fd);

        fd = open("/proc/self/gid_map", O_WRONLY);
        assert(fd >= 0);
        r = dprintf(fd, "0 %d 1\n", egid);
        assert(r >= 0);
        close(fd);
}

void test_setup(void) {
        int r;

        /*
         * Move into a new network and mount namespace both associated
         * with a new user namespace where the current eUID is mapped to
         * 0. Then create a a private instance of /run/netns. This ensures
         * that any network devices or network namespaces are private to
         * the test process.
         */

        test_unshare_user_namespace();

        r = unshare(CLONE_NEWNET | CLONE_NEWNS);
        assert(r >= 0);

        r = mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL);
        assert(r >= 0);

        r = mount(NULL, "/run", "tmpfs", 0, NULL);
        assert(r >= 0);

        r = mkdir("/run/netns", 0755);
        assert(r >= 0);
}
