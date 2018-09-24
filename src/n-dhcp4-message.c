/*
 * DHCPv4 Message
 *
 * XXX
 */

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4-private.h"

struct NDhcp4Incoming {
        struct {
                uint8_t *value;
                size_t size;
        } options[_N_DHCP4_OPTION_N];

        size_t n_message;
        NDhcp4Message message;
        /* @message must be the last member */
};

static void n_dhcp4_incoming_prefetch(NDhcp4Incoming *incoming, size_t *offset, uint8_t option, const uint8_t *raw, size_t n_raw) {
        uint8_t o, l;
        size_t pos;

        for (pos = 0; pos < n_raw; ) {
                o = raw[pos++];
                if (o == N_DHCP4_OPTION_PAD)
                        continue;
                if (o == N_DHCP4_OPTION_END)
                        return;

                /* bail out if no remaining space for length field */
                if (pos >= n_raw)
                        return;

                /* bail out if length exceeds the available space */
                l = raw[pos++];
                if (l > n_raw || pos > n_raw - l)
                        return;

                /* prefetch content if it matches @option */
                if (o == option) {
                        memcpy((uint8_t *)&incoming->message + *offset, raw + pos, l);
                        *offset += l;
                }

                pos += l;
        }
}

static void n_dhcp4_incoming_merge(NDhcp4Incoming *incoming, size_t *offset, uint8_t overload, uint8_t option) {
        uint8_t *m = (uint8_t *)&incoming->message;
        size_t pos;

        /*
         * Prefetch all options matching @option from the 3 sections,
         * concatenating their content. Remember the offset and size of the
         * option in our message state.
         */

        pos = *offset;

        /* prefetch option from OPTIONS */
        n_dhcp4_incoming_prefetch(incoming, offset, option,
                                  m + offsetof(NDhcp4Message, options),
                                  incoming->n_message - offsetof(NDhcp4Message, options));

        /* prefetch option from FILE */
        if (overload & N_DHCP4_OVERLOAD_FILE)
                n_dhcp4_incoming_prefetch(incoming, offset, option,
                                          m + offsetof(NDhcp4Message, file),
                                          sizeof(incoming->message.file));

        /* prefetch option from SNAME */
        if (overload & N_DHCP4_OVERLOAD_SNAME)
                n_dhcp4_incoming_prefetch(incoming, offset, option,
                                          m + offsetof(NDhcp4Message, sname),
                                          sizeof(incoming->message.sname));

        incoming->options[option].value = m + pos;
        incoming->options[option].size = *offset - pos;
}

static void n_dhcp4_incoming_linearize(NDhcp4Incoming *incoming) {
        uint8_t *m, o, l, overload;
        size_t i, pos, end, offset;

        /*
         * Linearize all OPTIONs of the incoming message. We know that
         * @incoming->message is preallocated to be big enough to hold the
         * entire linearized message _trailing_ the original copy. All we have
         * to do is walk the raw message in @incoming->message and for each
         * option we find, copy it into the trailing space, concatenating all
         * instances we find.
         *
         * Before we can copy the individual options, we must scan for the
         * OVERLOAD option. This is required so our prefetcher knows which data
         * arrays to scan for prefetching.
         *
         * So far, we require the OVERLOAD option to be present in the
         * options-array (which is obvious and a given). However, if the option
         * occurs multiple times outside of the options-array (i.e., SNAME or
         * FILE), we silently ignore them. The specification does not allow
         * multiple OVERLOAD options, anyway. Hence, this behavior only defines
         * what we do when we see broken implementations, and we currently seem
         * to support all styles we saw in the wild so far.
         */

        m = (uint8_t *)&incoming->message;
        offset = incoming->n_message;

        n_dhcp4_incoming_merge(incoming, &offset, 0, N_DHCP4_OPTION_OVERLOAD);
        if (incoming->options[N_DHCP4_OPTION_OVERLOAD].size >= 1)
                overload = *incoming->options[N_DHCP4_OPTION_OVERLOAD].value;
        else
                overload = 0;

        for (i = 0; i < 3; ++i) {
                if (i == 0) { /* walk OPTIONS */
                        pos = offsetof(NDhcp4Message, options);
                        end = incoming->n_message;
                } else if (i == 1) { /* walk FILE */
                        if (!(overload & N_DHCP4_OVERLOAD_FILE))
                                continue;

                        pos = offsetof(NDhcp4Message, file);
                        end = pos + sizeof(incoming->message.file);
                } else { /* walk SNAME */
                        if (!(overload & N_DHCP4_OVERLOAD_SNAME))
                                continue;

                        pos = offsetof(NDhcp4Message, sname);
                        end = pos + sizeof(incoming->message.sname);
                }

                while (pos < end) {
                        o = m[pos++];
                        if (o == N_DHCP4_OPTION_PAD)
                                continue;
                        if (o == N_DHCP4_OPTION_END)
                                break;
                        if (pos >= end)
                                break;

                        l = m[pos++];
                        if (l > end || pos > end - l)
                                break;

                        if (!incoming->options[o].value)
                                n_dhcp4_incoming_merge(incoming, &offset, overload, o);

                        pos += l;
                }
        }
}

int n_dhcp4_incoming_new(NDhcp4Incoming **incomingp, const void *raw, size_t n_raw) {
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *incoming = NULL;
        size_t size;

        assert(incomingp);

        if (n_raw < sizeof(NDhcp4Message))
                return -EINVAL;

        /*
         * Allocate enough space for book-keeping, a copy of @raw and trailing
         * space for linearized options. The trailing space must be big enough
         * to hold the entire options array unmodified (linearizing can only
         * make it smaller). Hence, just allocate enough space to hold a the
         * raw message without the header.
         */
        size = sizeof(*incoming) + n_raw - sizeof(NDhcp4Message);
        size += n_raw - sizeof(NDhcp4Header);

        incoming = calloc(1, size);
        if (!incoming)
                return -ENOMEM;

        incoming->n_message = n_raw;
        memcpy(&incoming->message, raw, n_raw);

        if (incoming->message.magic != htobe32(N_DHCP4_MESSAGE_MAGIC))
                return -EINVAL;

        /* linearize options */
        n_dhcp4_incoming_linearize(incoming);

        *incomingp = incoming;
        incoming = NULL;
        return 0;
}

NDhcp4Incoming *n_dhcp4_incoming_free(NDhcp4Incoming *incoming) {
        if (!incoming)
                return NULL;

        free(incoming);

        return NULL;
}

NDhcp4Header *n_dhcp4_incoming_get_header(NDhcp4Incoming *incoming) {
        return &incoming->message.header;
}

size_t n_dhcp4_incoming_get_raw(NDhcp4Incoming *incoming, const void **rawp) {
        if (rawp)
                *rawp = &incoming->message;
        return incoming->n_message;
}

int n_dhcp4_incoming_query(NDhcp4Incoming *incoming, uint8_t option, const void **datap, size_t *n_datap) {
        if (!incoming->options[option].value)
                return -ENODATA;

        if (datap)
                *datap = incoming->options[option].value;
        if (n_datap)
                *n_datap = incoming->options[option].size;
        return 0;
}
