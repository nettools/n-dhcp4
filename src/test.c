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
