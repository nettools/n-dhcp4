/*
 * Network Namespaces
 */

#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>
#include "util/netns.h"

/**
 * netns_get() - retrieve the current network namespace
 * @netnsp:             output argument to store netns fd
 *
 * This retrieves a file-descriptor to the current network namespace.
 */
void netns_get(int *netnsp) {
        *netnsp = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        assert(*netnsp >= 0);
}

/**
 * setns_set() - change the current network namespace
 * @netns:              netns to set, or -1
 *
 * This changes the current network namespace to the netns given by the
 * file-descriptor @netns. If @netns is not a valid file-descriptor (i.e., it
 * is smaller than 0), this creates a new anonymous network namespace and
 * enters it.
 */
void netns_set(int netns) {
        int r;

        if (netns >= 0)
                r = setns(netns, CLONE_NEWNET);
        else
                r = unshare(CLONE_NEWNET);
        assert(r >= 0);
}

/**
 * netns_new() - create a new network namespace
 * @netnsp:             output argument to store netns fd
 *
 * This creates a new network namespace and returns a netns fd that refers to
 * the new network namespace. Note that there is no native API to create an
 * anonymous network namespace, so this call has to temporarily switch to a new
 * network namespace (using unshare(2)). This temporary switch does not affect
 * any other threads or processes, however, it can be observed by other
 * processes.
 */
void netns_new(int *netnsp) {
        int r, oldns;

        netns_get(&oldns);

        r = unshare(CLONE_NEWNET);
        assert(r >= 0);

        netns_get(netnsp);
        netns_set(oldns);
}

/**
 * netns_pin() - pin network namespace in file-system
 * @netns:              netns to pin
 * @name:               name to pin netns under
 *
 * This pins the network namespace given as @netns in the file-system as
 * `/run/netns/@name`. It is the responsibility of the caller to guarantee
 * @name is not used by anyone else in parallel. This function will abort if
 * @name is already in use.
 */
void netns_pin(int netns, const char *name) {
        char *fd_path, *netns_path;
        int r, fd;

        r = asprintf(&fd_path, "/proc/self/fd/%d", netns);
        assert(r >= 0);

        r = asprintf(&netns_path, "/run/netns/%s", name);
        assert(r >= 0);

        fd = open(netns_path, O_RDONLY|O_CLOEXEC|O_CREAT|O_EXCL, 0);
        assert(fd >= 0);
        close(fd);

        r = mount(fd_path, netns_path, "none", MS_BIND, NULL);
        assert(r >= 0);

        free(netns_path);
        free(fd_path);
}

/**
 * netns_unpin() - unpin network namespace from file-system
 * @name:               name to unpin
 *
 * This removes a network namespace pin from the file-system. It expects the
 * pin to be located at `/run/netns/@name`. This function aborts if the pin
 * does not exist.
 */
void netns_unpin(const char *name) {
        char *netns_path;
        int r;

        r = asprintf(&netns_path, "/run/netns/%s", name);
        assert(r >= 0);

        r = umount2(netns_path, MNT_DETACH);
        assert(r >= 0);

        r = unlink(netns_path);
        assert(r >= 0);

        free(netns_path);
}
