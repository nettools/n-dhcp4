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
 * n_dhcp4_client_config_new() - allocate new client configuration
 * @configp:                    output argument for new client config
 *
 * This creates a new client configuration object. Client configurations are
 * unlinked objects that merely serve as collection of parameters. They do not
 * perform validity checks.
 *
 * The new client configuration is fully owned by the caller. They are
 * responsible to free the object if no longer needed.
 *
 * Return: 0 on success, negative error code on failure.
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
 * n_dhcp4_client_config_free() - destroy client configuration
 * @config:                     client configuration to operate on, or NULL
 *
 * This destroys a client configuration and deallocates all its resources. If
 * NULL is passed, this is a no-op.
 *
 * Return: NULL is returned.
 */
_public_ NDhcp4ClientConfig *n_dhcp4_client_config_free(NDhcp4ClientConfig *config) {
        if (!config)
                return NULL;

        free(config->client_id);
        free(config);

        return NULL;
}

/**
 * n_dhcp4_client_config_dup() - duplicate client configuration
 * @config:                     client configuration to operate on
 * @dupp:                       output argument for duplicate
 *
 * This duplicates the client configuration given as @config and returns it in
 * @dupp to the caller.
 *
 * Return: 0 on success, negative error code on failure.
 */
int n_dhcp4_client_config_dup(NDhcp4ClientConfig *config, NDhcp4ClientConfig **dupp) {
        _cleanup_(n_dhcp4_client_config_freep) NDhcp4ClientConfig *dup = NULL;
        int r;

        r = n_dhcp4_client_config_new(&dup);
        if (r)
                return r;

        dup->ifindex = config->ifindex;
        dup->transport = config->transport;
        memcpy(dup->mac, config->mac, sizeof(dup->mac));
        dup->n_mac = config->n_mac;
        memcpy(dup->broadcast_mac, config->broadcast_mac, sizeof(dup->broadcast_mac));
        dup->n_broadcast_mac = config->n_broadcast_mac;

        r = n_dhcp4_client_config_set_client_id(dup,
                                                config->client_id,
                                                config->n_client_id);
        if (r)
                return r;

        *dupp = dup;
        dup = NULL;
        return 0;
}

/**
 * n_dhcp4_client_config_set_ifindex() - set ifindex property
 * @config:                     client configuration to operate on
 * @ifindex:                    ifindex to set
 *
 * This sets the ifindex property of the client configuration. The ifindex
 * specifies the network device that a DHCP client will run on.
 */
_public_ void n_dhcp4_client_config_set_ifindex(NDhcp4ClientConfig *config, int ifindex) {
        config->ifindex = ifindex;
}

/**
 * n_dhcp4_client_config_set_transport() - set transport property
 * @config:                     client configuration to operate on
 * @transport:                  transport to set
 *
 * This sets the transport property of the client configuration. The transport
 * defines the hardware transport of the network device that a DHCP client
 * runs on.
 *
 * This takes one of the N_DHCP4_TRANSPORT_* identifiers as argument.
 */
_public_ void n_dhcp4_client_config_set_transport(NDhcp4ClientConfig *config, unsigned int transport) {
        config->transport = transport;
}

/**
 * n_dhcp4_client_config_set_mac() - set mac property
 * @config:                     client configuration to operate on
 * @mac:                        hardware address to set
 * @n_mac:                      length of the hardware address
 *
 * This sets the mac property of the client configuration. It specifies the
 * hardware address of the local interface that the DHCP client runs on.
 *
 * This function copies the specified hardware address into @config. Any
 * hardware address is supported. It is up to the consumer of the client
 * configuration to verify the validity of the hardware address.
 *
 * Note: This function may truncate the hardware address internally, but
 *       retains the original length. The consumer of this configuration can
 *       thus tell whether the data was truncated and will refuse it.
 *       The internal buffer is big enough to hold any hardware address of all
 *       supported transports. Thus, truncation only happens if you use
 *       unsupported transports, and those will be rejected, anyway.
 */
_public_ void n_dhcp4_client_config_set_mac(NDhcp4ClientConfig *config, const uint8_t *mac, size_t n_mac) {
        config->n_mac = n_mac;
        memcpy(config->mac, mac, MIN(n_mac, sizeof(config->mac)));
}

/**
 * n_dhcp4_client_config_set_broadcast_mac() - set broadcast-mac property
 * @config:                     client configuration to operate on
 * @mac:                        hardware address to set
 * @n_mac:                      length of the hardware address
 *
 * This sets the broadcast-mac property of the client configuration. It
 * specifies the destination hardware address to use for broadcasts on the
 * local interface that the DHCP client runs on.
 *
 * This function copies the specified hardware address into @config. Any
 * hardware address is supported. It is up to the consumer of the client
 * configuration to verify the validity of the hardware address.
 *
 * Note: This function may truncate the hardware address internally, but
 *       retains the original length. The consumer of this configuration can
 *       thus tell whether the data was truncated and will refuse it.
 *       The internal buffer is big enough to hold any hardware address of all
 *       supported transports. Thus, truncation only happens if you use
 *       unsupported transports, and those will be rejected, anyway.
 */
_public_ void n_dhcp4_client_config_set_broadcast_mac(NDhcp4ClientConfig *config, const uint8_t *mac, size_t n_mac) {
        config->n_broadcast_mac = n_mac;
        memcpy(config->broadcast_mac, mac, MIN(n_mac, sizeof(config->broadcast_mac)));
}

/**
 * n_dhcp4_client_config_set_client_id() - set client-id property
 * @config:                     client configuration to operate on
 * @id:                         client id
 * @n_id:                       length of the client id in bytes
 *
 * This sets the client-id property of @config. It copies the entire client-id
 * buffer into the configuration.
 *
 * Return: 0 on success, negative error code on failure.
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
_public_ int n_dhcp4_client_new(NDhcp4Client **clientp, NDhcp4ClientConfig *config) {
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

        r = n_dhcp4_client_config_dup(config, &client->config);
        if (r)
                return r;

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

        n_dhcp4_client_config_free(client->config);
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
