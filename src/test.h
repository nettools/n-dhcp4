#pragma once

/*
 * Test Helpers
 * Bunch of helpers to setup the environment for networking tests. This
 * includes net-namespace setups, veth setups, and more.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void test_socket_new(int netns, int *sockfdp, int family, int ifindex);

void test_add_ip(int netns, int ifindex, const struct in_addr *addr, unsigned int prefix);
void test_del_ip(int netns, int ifindex, const struct in_addr *addr, unsigned int prefix);

void test_veth_new(int parent_ns,
                   int *parent_indexp,
                   struct ether_addr *parent_macp,
                   int child_ns,
                   int *child_indexp,
                   struct ether_addr *child_macp);

static inline void test_unshare_user_namespace(void) {
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

static inline void test_setup(void) {
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
