/*
 * Server Side of the Dynamic Host Configuration Protocol for IPv4
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
 * n_dhcp4_server_config_new() - XXX
 */
_public_ int n_dhcp4_server_config_new(NDhcp4ServerConfig **configp) {
        _cleanup_(n_dhcp4_server_config_freep) NDhcp4ServerConfig *config = NULL;

        config = calloc(1, sizeof(*config));
        if (!config)
                return -ENOMEM;

        *config = (NDhcp4ServerConfig)N_DHCP4_SERVER_CONFIG_NULL(*config);

        *configp = config;
        config = NULL;
        return 0;
}

/**
 * n_dhcp4_server_config_free() - XXX
 */
_public_ NDhcp4ServerConfig *n_dhcp4_server_config_free(NDhcp4ServerConfig *config) {
        if (!config)
                return NULL;

        free(config);

        return NULL;
}

/**
 * n_dhcp4_server_config_set_ifindex() - XXX
 */
_public_ void n_dhcp4_server_config_set_ifindex(NDhcp4ServerConfig *config, int ifindex) {
        config->ifindex = ifindex;
}

/**
 * n_dhcp4_s_event_node_new() - XXX
 */
int n_dhcp4_s_event_node_new(NDhcp4SEventNode **nodep) {
        NDhcp4SEventNode *node;

        node = calloc(1, sizeof(*node));
        if (!node)
                return -ENOMEM;

        *node = (NDhcp4SEventNode)N_DHCP4_S_EVENT_NODE_NULL(*node);

        *nodep = node;
        return 0;
}

/**
 * n_dhcp4_s_event_node_free() - XXX
 */
NDhcp4SEventNode *n_dhcp4_s_event_node_free(NDhcp4SEventNode *node) {
        if (!node)
                return NULL;

        c_list_unlink(&node->server_link);
        free(node);

        return NULL;
}

/**
 * n_dhcp4_server_new() - XXX
 */
_public_ int n_dhcp4_server_new(NDhcp4Server **serverp) {
        _cleanup_(n_dhcp4_server_unrefp) NDhcp4Server *server = NULL;
        struct epoll_event ev = {
                .events = EPOLLIN,
        };
        int r;

        assert(serverp);

        server = malloc(sizeof(*server));
        if (!server)
                return -ENOMEM;

        *server = (NDhcp4Server)N_DHCP4_SERVER_NULL(*server);

        server->fd_epoll = epoll_create1(EPOLL_CLOEXEC);
        if (server->fd_epoll < 0)
                return -errno;

        server->fd_timer = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (server->fd_timer < 0)
                return -errno;

        ev.data.u32 = N_DHCP4_SERVER_EPOLL_TIMER;
        r = epoll_ctl(server->fd_epoll, EPOLL_CTL_ADD, server->fd_timer, &ev);
        if (r < 0)
                return -errno;

        *serverp = server;
        server = NULL;
        return 0;
}

static void n_dhcp4_server_free(NDhcp4Server *server) {
        NDhcp4SEventNode *node, *t_node;

        c_list_for_each_entry_safe(node, t_node, &server->event_list, server_link)
                n_dhcp4_s_event_node_free(node);

        if (server->fd_timer >= 0) {
                epoll_ctl(server->fd_epoll, EPOLL_CTL_DEL, server->fd_timer, NULL);
                close(server->fd_timer);
        }

        if (server->fd_epoll >= 0)
                close(server->fd_epoll);

        free(server);
}

/**
 * n_dhcp4_server_ref() - XXX
 */
_public_ NDhcp4Server *n_dhcp4_server_ref(NDhcp4Server *server) {
        if (server)
                ++server->n_refs;
        return server;
}

/**
 * n_dhcp4_server_unref() - XXX
 */
_public_ NDhcp4Server *n_dhcp4_server_unref(NDhcp4Server *server) {
        if (server && !--server->n_refs)
                n_dhcp4_server_free(server);
        return NULL;
}

/**
 * n_dhcp4_server_raise() - XXX
 */
int n_dhcp4_server_raise(NDhcp4Server *server, NDhcp4SEventNode **nodep, unsigned int event) {
        NDhcp4SEventNode *node;
        int r;

        r = n_dhcp4_s_event_node_new(&node);
        if (r)
                return r;

        node->event.event = event;
        c_list_link_tail(&server->event_list, &node->server_link);

        if (nodep)
                *nodep = node;
        return 0;
}

/**
 * n_dhcp4_server_get_fd() - XXX
 */
_public_ void n_dhcp4_server_get_fd(NDhcp4Server *server, int *fdp) {
        *fdp = server->fd_epoll;
}

static int n_dhcp4_server_dispatch_timer(NDhcp4Server *server, struct epoll_event *event) {
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
                r = read(server->fd_timer, &v, sizeof(v));
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
                 * XXX
                 */
        }

        return 0;
}

static void n_dhcp4_server_arm_timer(NDhcp4Server *server) {
        uint64_t timeout = 0;
        int r;

        /* XXX: avoid syscall if it didn't change */

        r = timerfd_settime(server->fd_timer,
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

static int n_dhcp4_server_dispatch_io(NDhcp4Server *server, struct epoll_event *event) {
        return -ENOTRECOVERABLE;
}

/**
 * n_dhcp4_server_dispatch() - XXX
 */
_public_ int n_dhcp4_server_dispatch(NDhcp4Server *server) {
        struct epoll_event events[2];
        int n, i, r = 0;

        n = epoll_wait(server->fd_epoll, events, sizeof(events) / sizeof(*events), 0);
        if (n < 0) {
                /* Linux never returns EINTR if `timeout == 0'. */
                return -errno;
        }

        server->preempted = false;

        for (i = 0; i < n; ++i) {
                switch (events[i].data.u32) {
                case N_DHCP4_SERVER_EPOLL_TIMER:
                        r = n_dhcp4_server_dispatch_timer(server, events + i);
                        break;
                case N_DHCP4_SERVER_EPOLL_IO:
                        r = n_dhcp4_server_dispatch_io(server, events + i);
                        break;
                default:
                        assert(0);
                        r = 0;
                        break;
                }

                if (r)
                        return r;
        }

        n_dhcp4_server_arm_timer(server);

        return server->preempted ? N_DHCP4_E_PREEMPTED : 0;
}

/**
 * n_dhcp4_server_pop_event() - XXX
 */
_public_ int n_dhcp4_server_pop_event(NDhcp4Server *server, NDhcp4ServerEvent **eventp) {
        NDhcp4SEventNode *node, *t_node;

        c_list_for_each_entry_safe(node, t_node, &server->event_list, server_link) {
                if (node->is_public) {
                        n_dhcp4_s_event_node_free(node);
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
 * n_dhcp4_server_add_ip() - XXX
 */
_public_ int n_dhcp4_server_add_ip(NDhcp4Server *server, NDhcp4ServerIp **ipp, struct in_addr addr) {
        _cleanup_(n_dhcp4_server_ip_freep) NDhcp4ServerIp *ip = NULL;

        /* XXX: support more than one address */
        if (server->connection.ip)
                return -EBUSY;

        ip = malloc(sizeof(*ip));
        if (!ip)
                return -ENOMEM;

        *ip = (NDhcp4ServerIp)N_DHCP4_SERVER_IP_NULL(*ip);

        n_dhcp4_s_connection_ip_init(&ip.ip, addr);
        n_dhcp4_s_conneciton_ip_link(&ip.ip, &server->connection);

        *ipp = ip;
        ip = NULL;
        return 0;
}

/**
 * n_dhcp4_server_ip_free() - XXX
 */
_public_ NDhcp4ServerIp *n_dhcp4_server_ip_free(NDhcp4ServerIp *ip) {
        if (!ip)
                return NULL;

        n_dhcp4_s_connection_ip_unlink(&ip.ip);
        n_dhcp4_s_connection_ip_deinit(&ip.ip);

        free(ip);
        return NULL;
}
