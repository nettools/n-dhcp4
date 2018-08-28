/*
 * Client Side of the Dynamic Host Configuration Protocol for IPv4
 *
 * XXX
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"

enum {
        N_DHCP4_STATE_INIT,
        N_DHCP4_STATE_SELECTING,
        N_DHCP4_STATE_INIT_REBOOT,
        N_DHCP4_STATE_REBOOTING,
        N_DHCP4_STATE_REQUESTING,
        N_DHCP4_STATE_BOUND,
        N_DHCP4_STATE_RENEWING,
        N_DHCP4_STATE_REBINDING,
};

_public_ int n_dhcp4_client_new(NDhcp4Client **clientp) {
        _cleanup_(n_dhcp4_client_freep) NDhcp4Client *client = NULL;
        struct epoll_event ev;
        int r;

        assert(clientp);

        client = calloc(1, sizeof(*client));
        if (!client)
                return -ENOMEM;

        client->state = N_DHCP4_STATE_INIT;
        client->efd = -1;
        client->tfd = -1;
        client->pfd = -1;
        client->ufd = -1;

        client->efd = epoll_create1(EPOLL_CLOEXEC);
        if (client->efd < 0)
                return -errno;

        client->tfd = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (client->tfd < 0)
                return -errno;

        ev = (struct epoll_event){ .events = EPOLLIN, .data.fd = client->tfd };
        r = epoll_ctl(client->efd, EPOLL_CTL_ADD, client->tfd, &ev);
        if (r < 0)
                return -errno;

        *clientp = client;
        client = NULL;
        return 0;
}

_public_ NDhcp4Client *n_dhcp4_client_free(NDhcp4Client *client) {
        if (!client)
                return NULL;

        if (client->ufd >= 0) {
                epoll_ctl(client->efd, EPOLL_CTL_DEL, client->ufd, NULL);
                close(client->ufd);
        }
        if (client->pfd >= 0) {
                epoll_ctl(client->efd, EPOLL_CTL_DEL, client->pfd, NULL);
                close(client->pfd);
        }
        if (client->tfd >= 0) {
                epoll_ctl(client->efd, EPOLL_CTL_DEL, client->tfd, NULL);
                close(client->tfd);
        }
        if (client->efd >= 0)
                close(client->efd);
        free(client);

        return NULL;
}

_public_ int n_dhcp4_client_get_fd(NDhcp4Client *client) {
        return client->efd;
}

static int n_dhcp4_client_transition_t1(NDhcp4Client *client) {
        switch (client->state) {
        case N_DHCP4_STATE_BOUND:
                client->state = N_DHCP4_STATE_RENEWING;
                break;

        case N_DHCP4_STATE_INIT:
        case N_DHCP4_STATE_SELECTING:
        case N_DHCP4_STATE_INIT_REBOOT:
        case N_DHCP4_STATE_REBOOTING:
        case N_DHCP4_STATE_REQUESTING:
        case N_DHCP4_STATE_RENEWING:
        case N_DHCP4_STATE_REBINDING:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_transition_t2(NDhcp4Client *client) {
        switch (client->state) {
        case N_DHCP4_STATE_BOUND:
        case N_DHCP4_STATE_RENEWING:
                client->state = N_DHCP4_STATE_REBINDING;
                break;

        case N_DHCP4_STATE_INIT:
        case N_DHCP4_STATE_SELECTING:
        case N_DHCP4_STATE_INIT_REBOOT:
        case N_DHCP4_STATE_REBOOTING:
        case N_DHCP4_STATE_REQUESTING:
        case N_DHCP4_STATE_REBINDING:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_transition_lifetime(NDhcp4Client *client) {
        switch (client->state) {
        case N_DHCP4_STATE_BOUND:
        case N_DHCP4_STATE_RENEWING:
        case N_DHCP4_STATE_REBINDING:
                client->state = N_DHCP4_STATE_INIT;
                break;

        case N_DHCP4_STATE_INIT:
        case N_DHCP4_STATE_SELECTING:
        case N_DHCP4_STATE_INIT_REBOOT:
        case N_DHCP4_STATE_REBOOTING:
        case N_DHCP4_STATE_REQUESTING:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_transition_offer(NDhcp4Client *client) {
        switch (client->state) {
        case N_DHCP4_STATE_SELECTING:
                client->state = N_DHCP4_STATE_REQUESTING;
                break;

        case N_DHCP4_STATE_INIT:
        case N_DHCP4_STATE_INIT_REBOOT:
        case N_DHCP4_STATE_REBOOTING:
        case N_DHCP4_STATE_REQUESTING:
        case N_DHCP4_STATE_BOUND:
        case N_DHCP4_STATE_RENEWING:
        case N_DHCP4_STATE_REBINDING:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_transition_ack(NDhcp4Client *client) {
        switch (client->state) {
        case N_DHCP4_STATE_INIT:
        case N_DHCP4_STATE_SELECTING:
        case N_DHCP4_STATE_INIT_REBOOT:
        case N_DHCP4_STATE_REBOOTING:
        case N_DHCP4_STATE_REQUESTING:
        case N_DHCP4_STATE_BOUND:
        case N_DHCP4_STATE_RENEWING:
        case N_DHCP4_STATE_REBINDING:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_transition_nak(NDhcp4Client *client) {
        switch (client->state) {
        case N_DHCP4_STATE_REBOOTING:
        case N_DHCP4_STATE_REQUESTING:
        case N_DHCP4_STATE_RENEWING:
        case N_DHCP4_STATE_REBINDING:
                client->state = N_DHCP4_STATE_INIT;
                break;

        case N_DHCP4_STATE_SELECTING:
        case N_DHCP4_STATE_INIT_REBOOT:
        case N_DHCP4_STATE_INIT:
        case N_DHCP4_STATE_BOUND:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_dispatch_tfd(NDhcp4Client *client, unsigned int events) {
        uint64_t expirations, now;
        struct timespec ts;
        int r;

        if (events & (EPOLLHUP | EPOLLERR))
                return -EIO;

        r = read(client->tfd, &expirations, sizeof(expirations));
        if (r < 0) {
                if (errno == EAGAIN)
                        return 0;
                return -errno;
        }

        if (expirations > 0) {
                r = clock_gettime(CLOCK_BOOTTIME, &ts);
                if (r < 0)
                        return -errno;

                now = ts.tv_sec * 1000ULL * 1000ULL + ts.tv_nsec / 1000ULL;
                if (now >= client->u_lifetime) {
                        client->u_t1 = 0;
                        client->u_t2 = 0;
                        client->u_lifetime = 0;
                        return n_dhcp4_client_transition_lifetime(client);
                } else if (now >= client->u_t2) {
                        client->u_t1 = 0;
                        client->u_t2 = 0;
                        return n_dhcp4_client_transition_t2(client);
                } else if (now >= client->u_t1) {
                        client->u_t1 = 0;
                        return n_dhcp4_client_transition_t1(client);
                }
        }

        return 0;
}

static int n_dhcp4_client_dispatch_msg(NDhcp4Client *client, NDhcp4Incoming *incoming) {
        const void *value;
        size_t size;
        int r;

        r = n_dhcp4_incoming_query(incoming, N_DHCP4_OPTION_MESSAGE_TYPE, &value, &size);
        if (r == -ENODATA || size != 1)
                return 0; /* ignore messages with invalid message type */
        else if (r < 0)
                return r;

        switch (*(const uint8_t *)value) {
        case N_DHCP4_MESSAGE_OFFER:
                return n_dhcp4_client_transition_offer(client);
        case N_DHCP4_MESSAGE_ACK:
                return n_dhcp4_client_transition_ack(client);
        case N_DHCP4_MESSAGE_NAK:
                return n_dhcp4_client_transition_nak(client);
        default:
                /* ignore unknown message types */
                return 0;
        }
}

static int n_dhcp4_client_dispatch_pfd(NDhcp4Client *client, unsigned int events) {
        if (events & EPOLLIN) {
                /* XXX */
                n_dhcp4_client_dispatch_msg(client, NULL);
                return 0;
        }

        if (events & (EPOLLHUP | EPOLLERR))
                return -EIO;

        return 0;
}

static int n_dhcp4_client_dispatch_ufd(NDhcp4Client *client, unsigned int events) {
        if (events & EPOLLIN) {
                /* XXX */
                n_dhcp4_client_dispatch_msg(client, NULL);
                return 0;
        }

        if (events & (EPOLLHUP | EPOLLERR))
                return -EIO;

        return 0;
}

_public_ int n_dhcp4_client_dispatch(NDhcp4Client *client) {
        struct epoll_event ev;
        int r;

        r = epoll_wait(client->efd, &ev, 1, 0);
        if (r < 0) {
                r = -errno;
                goto exit;
        }

        if (r > 0) {
                if (ev.data.fd == client->tfd)
                        r = n_dhcp4_client_dispatch_tfd(client, ev.events);
                else if (ev.data.fd == client->pfd)
                        r = n_dhcp4_client_dispatch_pfd(client, ev.events);
                else if (ev.data.fd == client->ufd)
                        r = n_dhcp4_client_dispatch_ufd(client, ev.events);
                else
                        r = 0;
        }

exit:
        if (r < 0) {
                /* XXX */
                client->state = N_DHCP4_STATE_INIT;
        }
        return r;
}
