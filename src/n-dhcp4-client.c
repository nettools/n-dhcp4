/*
 * Client Side of the Dynamic Host Configuration Protocol for IPv4
 *
 * XXX
 */

#include <assert.h>
#include <c-list.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"
#include "util/packet.h"

/**
 * n_dhcp4_client_config_new() - XXX
 */
_public_ int n_dhcp4_client_config_new(NDhcp4ClientConfig **configp) {
        _cleanup_(n_dhcp4_client_config_freep) NDhcp4ClientConfig *config = NULL;

        config = calloc(1, sizeof(*config));
        if (!config)
                return -ENOMEM;

        *config = (NDhcp4ClientConfig)N_DHCP4_CLIENT_CONFIG_NULL(*config);

        *configp = config;
        config = NULL;
        return 0;
}

/**
 * n_dhcp4_client_config_free() - XXX
 */
_public_ NDhcp4ClientConfig *n_dhcp4_client_config_free(NDhcp4ClientConfig *config) {
        if (!config)
                return NULL;

        free(config->client_id);
        free(config);

        return NULL;
}

/**
 * n_dhcp4_client_config_set_ifindex() - XXX
 */
_public_ void n_dhcp4_client_config_set_ifindex(NDhcp4ClientConfig *config, int ifindex) {
        config->ifindex = ifindex;
}

/**
 * n_dhcp4_client_config_set_transport() - XXX
 */
_public_ void n_dhcp4_client_config_set_transport(NDhcp4ClientConfig *config, unsigned int transport) {
        config->transport = transport;
}

/**
 * n_dhcp4_client_config_set_mac() - XXX
 */
_public_ void n_dhcp4_client_config_set_mac(NDhcp4ClientConfig *config, const uint8_t *mac, size_t n_mac) {
        config->n_mac = n_mac;
        memcpy(config->mac, mac, MIN(n_mac, sizeof(config->mac)));
}

/**
 * n_dhcp4_client_config_set_broadcast_mac() - XXX
 */
_public_ void n_dhcp4_client_config_set_broadcast_mac(NDhcp4ClientConfig *config, const uint8_t *mac, size_t n_mac) {
        config->n_broadcast_mac = n_mac;
        memcpy(config->broadcast_mac, mac, MIN(n_mac, sizeof(config->broadcast_mac)));
}

/**
 * n_dhcp4_client_config_set_client_id() - XXX
 */
_public_ int n_dhcp4_client_config_set_client_id(NDhcp4ClientConfig *config, const uint8_t *id, size_t n_id) {
        uint8_t *t;

        t = malloc(n_id + 1);
        if (!t)
                return -ENOMEM;

        free(config->client_id);
        config->client_id = t;
        config->n_client_id = n_id;

        memcpy(config->client_id, id, n_id);
        config->client_id[n_id] = 0; /* safety 0 for debugging */

        return 0;
}

/**
 * n_dhcp4_c_event_node_new() - XXX
 */
int n_dhcp4_c_event_node_new(NDhcp4CEventNode **nodep) {
        NDhcp4CEventNode *node;

        node = calloc(1, sizeof(*node));
        if (!node)
                return -ENOMEM;

        *node = (NDhcp4CEventNode)N_DHCP4_C_EVENT_NODE_NULL(*node);

        *nodep = node;
        return 0;
}

/**
 * n_dhcp4_c_event_node_free() - XXX
 */
NDhcp4CEventNode *n_dhcp4_c_event_node_free(NDhcp4CEventNode *node) {
        if (!node)
                return NULL;

        c_list_unlink(&node->probe_link);
        c_list_unlink(&node->client_link);
        free(node);

        return NULL;
}

/**
 * n_dhcp4_client_new() - XXX
 */
_public_ int n_dhcp4_client_new(NDhcp4Client **clientp) {
        _cleanup_(n_dhcp4_client_unrefp) NDhcp4Client *client = NULL;
        struct epoll_event ev = {
                .events = EPOLLIN,
        };
        int r;

        assert(clientp);

        client = malloc(sizeof(*client));
        if (!client)
                return -ENOMEM;

        *client = (NDhcp4Client)N_DHCP4_CLIENT_NULL(*client);

        client->fd_epoll = epoll_create1(EPOLL_CLOEXEC);
        if (client->fd_epoll < 0)
                return -errno;

        client->fd_timer = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (client->fd_timer < 0)
                return -errno;

        ev.data.u32 = N_DHCP4_CLIENT_EPOLL_TIMER;
        r = epoll_ctl(client->fd_epoll, EPOLL_CTL_ADD, client->fd_timer, &ev);
        if (r < 0)
                return -errno;

        *clientp = client;
        client = NULL;
        return 0;
}

static void n_dhcp4_client_free(NDhcp4Client *client) {
        NDhcp4CEventNode *node, *t_node;

        assert(!client->current_probe);

        c_list_for_each_entry_safe(node, t_node, &client->event_list, client_link)
                n_dhcp4_c_event_node_free(node);

        if (client->fd_timer >= 0) {
                epoll_ctl(client->fd_epoll, EPOLL_CTL_DEL, client->fd_timer, NULL);
                close(client->fd_timer);
        }

        if (client->fd_epoll >= 0)
                close(client->fd_epoll);

        free(client);
}

/**
 * n_dhcp4_client_ref() - XXX
 */
_public_ NDhcp4Client *n_dhcp4_client_ref(NDhcp4Client *client) {
        if (client)
                ++client->n_refs;
        return client;
}

/**
 * n_dhcp4_client_unref() - XXX
 */
_public_ NDhcp4Client *n_dhcp4_client_unref(NDhcp4Client *client) {
        if (client && !--client->n_refs)
                n_dhcp4_client_free(client);
        return NULL;
}

/**
 * n_dhcp4_client_raise() - XXX
 */
int n_dhcp4_client_raise(NDhcp4Client *client, NDhcp4CEventNode **nodep, unsigned int event) {
        NDhcp4CEventNode *node;
        int r;

        r = n_dhcp4_c_event_node_new(&node);
        if (r)
                return r;

        node->event.event = event;
        c_list_link_tail(&client->event_list, &node->client_link);

        if (nodep)
                *nodep = node;
        return 0;
}

/**
 * n_dhcp4_client_get_fd() - XXX
 */
_public_ void n_dhcp4_client_get_fd(NDhcp4Client *client, int *fdp) {
        *fdp = client->fd_epoll;
}

static int n_dhcp4_client_dispatch_timer(NDhcp4Client *client, struct epoll_event *event) {
        uint64_t v;
        int r;

        if (event->events & (EPOLLHUP | EPOLLERR)) {
                /*
                 * There is no way to handle either gracefully. If we ignored
                 * them, we would busy-loop, so lets rather forward the error
                 * to the caller.
                 */
                return -ENOTRECOVERABLE;
        }

        if (event->events & EPOLLIN) {
                r = read(client->fd_timer, &v, sizeof(v));
                if (r < 0) {
                        if (errno == EAGAIN) {
                                /*
                                 * There are no more pending events, so nothing
                                 * to be done. Return to the caller.
                                 */
                                return 0;
                        }

                        /*
                         * Something failed. We use CLOCK_BOOTTIME/MONOTONIC,
                         * so ECANCELED cannot happen. Hence, there is no error
                         * that we could gracefully handle. Fail hard and let
                         * the caller deal with it.
                         */
                        return -errno;
                } else if (r != sizeof(v) || v == 0) {
                        /*
                         * Kernel guarantees 8-byte reads, and only to return
                         * data if at least one timer triggered; fail hard if
                         * it suddenly starts exposing unexpected behavior.
                         */
                        return -ENOTRECOVERABLE;
                }

                /*
                 * Forward the timer-event to the active probe. Timers should
                 * not fire if there is no probe running, but lets ignore them
                 * for now, so probe-internals are not leaked to this generic
                 * client dispatcher.
                 */
                if (client->current_probe) {
                        r = n_dhcp4_client_probe_dispatch_timer(client->current_probe);
                        if (r)
                                return r;
                }
        }

        return 0;
}

static void n_dhcp4_client_arm_timer(NDhcp4Client *client) {
        uint64_t timeout = 0;
        int r;

        if (client->current_probe)
                n_dhcp4_client_probe_get_timeout(client->current_probe, &timeout);

        /* XXX: avoid syscall if it didn't change */

        r = timerfd_settime(client->fd_timer,
                            TFD_TIMER_ABSTIME,
                            &(struct itimerspec){
                                .it_value = {
                                        .tv_sec = timeout / UINT64_C(1000000000),
                                        .tv_nsec = timeout % UINT64_C(1000000000),
                                },
                            },
                            NULL);
        assert(r >= 0);
}

static int n_dhcp4_client_dispatch_io(NDhcp4Client *client, struct epoll_event *event) {
        int r;

        if (client->current_probe)
                r = n_dhcp4_client_probe_dispatch_io(client->current_probe,
                                                     event->events);
        else
                return -ENOTRECOVERABLE;

        return r;
}

/**
 * n_dhcp4_client_dispatch() - XXX
 */
_public_ int n_dhcp4_client_dispatch(NDhcp4Client *client) {
        struct epoll_event events[2];
        int n, i, r = 0;

        n = epoll_wait(client->fd_epoll, events, sizeof(events) / sizeof(*events), 0);
        if (n < 0) {
                /* Linux never returns EINTR if `timeout == 0'. */
                return -errno;
        }

        client->preempted = false;

        for (i = 0; i < n; ++i) {
                switch (events[i].data.u32) {
                case N_DHCP4_CLIENT_EPOLL_TIMER:
                        r = n_dhcp4_client_dispatch_timer(client, events + i);
                        break;
                case N_DHCP4_CLIENT_EPOLL_IO:
                        r = n_dhcp4_client_dispatch_io(client, events + i);
                        break;
                default:
                        assert(0);
                        r = 0;
                        break;
                }

                if (r)
                        return r;
        }

        n_dhcp4_client_arm_timer(client);

        return client->preempted ? N_DHCP4_E_PREEMPTED : 0;
}

/**
 * n_dhcp4_client_pop_event() - XXX
 */
_public_ int n_dhcp4_client_pop_event(NDhcp4Client *client, NDhcp4ClientEvent **eventp) {
        NDhcp4CEventNode *node, *t_node;

        c_list_for_each_entry_safe(node, t_node, &client->event_list, client_link) {
                if (node->is_public) {
                        n_dhcp4_c_event_node_free(node);
                        continue;
                }

                node->is_public = true;
                *eventp = &node->event;
                return 0;
        }

        *eventp = NULL;
        return 0;
}

/**
 * n_dhcp4_client_update_mtu() - XXX
 */
_public_ int n_dhcp4_client_update_mtu(NDhcp4Client *client, uint16_t mtu) {
        int r;

        if (mtu == client->mtu)
                return 0;

        if (client->current_probe) {
                r = n_dhcp4_client_probe_update_mtu(client->current_probe, mtu);
                if (r)
                        return r;
        }

        client->mtu = mtu;
        return 0;
}

/**
 * n_dhcp4_client_probe() - XXX
 */
_public_ int n_dhcp4_client_probe(NDhcp4Client *client,
                                  NDhcp4ClientProbe **probep,
                                  NDhcp4ClientProbeConfig *config) {
        _cleanup_(n_dhcp4_client_probe_freep) NDhcp4ClientProbe *probe = NULL;
        int r;

        r = n_dhcp4_client_probe_new(&probe, client);
        if (r)
                return r;

        if (client->current_probe) {
                r = n_dhcp4_client_probe_raise(client->current_probe,
                                               NULL,
                                               N_DHCP4_CLIENT_EVENT_CANCELLED);
                if (r)
                        return r;

                n_dhcp4_client_probe_uninstall(client->current_probe);
        }

        r = n_dhcp4_client_probe_install(probe);
        if (r)
                return r;

        *probep = probe;
        probe = NULL;
        return 0;
}
