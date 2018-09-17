#pragma once

/*
 * Test Helpers
 * Bunch of helpers to setup the environment for networking tests. This
 * includes net-namespace setups, veth setups, and more.
 */

#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>

void test_netns_new(int *netnsp);
void test_netns_get(int *netnsp);
void test_netns_set(int netns);

void test_socket_new(int netns, int *sockfdp, int family, int ifindex);

void test_add_ip(int netns, int ifindex, const struct in_addr *addr, unsigned int prefix);
void test_del_ip(int netns, int ifindex, const struct in_addr *addr, unsigned int prefix);

void test_veth_new(int parent_ns,
                   int *parent_indexp,
                   struct ether_addr *parent_macp,
                   int child_ns,
                   int *child_indexp,
                   struct ether_addr *child_macp);

void test_bridge_new(int netns,
                     int *indexp,
                     struct ether_addr *macp);

void test_enslave_link(int netns, int master, int slave);

int test_setup(void);
