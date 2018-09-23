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

/**
 * N_DHCP4_MESSAGE_MAX_PHDR - maximum protocol header size
 *
 * All DHCP4 messages-limits specify the size of the entire packet including
 * the protocol layer (i.e., including the IP headers and UDP headers). To
 * calculate the size we have remaining for the actual DHCP message, we need to
 * substract the maximum possible header-length the linux-kernel might prepend
 * to our messages. This turns out to be the maximum IP-header size (including
 * optional IP headers, hence 60 bytes) plus the UDP header size (i.e., 8
 * bytes).
 */
#define N_DHCP4_MESSAGE_MAX_PHDR (N_DHCP4_NETWORK_IP_MAXIMUM_HEADER_SIZE + sizeof(struct udphdr))

struct NDhcp4Outgoing {
        NDhcp4Message *message;
        size_t n_message;
        size_t i_message;
        size_t max_size;

        uint8_t overload : 2;
};

struct NDhcp4Incoming {
        struct {
                uint8_t *value;
                size_t size;
        } options[_N_DHCP4_OPTION_N];

        size_t n_message;
        NDhcp4Message message;
        /* @message must be the last member */
};

int n_dhcp4_outgoing_new(NDhcp4Outgoing **outgoingp, size_t max_size, uint8_t overload) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *outgoing = NULL;

        assert(outgoingp);
        assert(!(overload & ~(N_DHCP4_OVERLOAD_FILE | N_DHCP4_OVERLOAD_SNAME)));

        /*
         * Make sure the minimum limit is bigger than the maximum protocol
         * header plus the DHCP-message-header plus a single OPTION_END byte.
         */
        static_assert(N_DHCP4_NETWORK_IP_MINIMUM_MAX_SIZE >= N_DHCP4_MESSAGE_MAX_PHDR + sizeof(NDhcp4Message) + 1, "Invalid minimum IP packet limit");

        outgoing = calloc(1, sizeof(*outgoing));
        if (!outgoing)
                return -ENOMEM;

        outgoing->n_message = N_DHCP4_NETWORK_IP_MINIMUM_MAX_SIZE - N_DHCP4_MESSAGE_MAX_PHDR;
        outgoing->i_message = offsetof(NDhcp4Message, options);
        outgoing->max_size = outgoing->n_message;
        outgoing->overload = overload;

        if (max_size > N_DHCP4_NETWORK_IP_MINIMUM_MAX_SIZE)
                outgoing->max_size = max_size - N_DHCP4_MESSAGE_MAX_PHDR;

        outgoing->message = calloc(1, outgoing->n_message);
        if (!outgoing->message)
                return -ENOMEM;

        *outgoing->message = (NDhcp4Message)N_DHCP4_MESSAGE_NULL;
        outgoing->message->options[0] = N_DHCP4_OPTION_END;

        *outgoingp = outgoing;
        outgoing = NULL;
        return 0;
}

NDhcp4Outgoing *n_dhcp4_outgoing_free(NDhcp4Outgoing *outgoing) {
        if (!outgoing)
                return NULL;

        free(outgoing->message);
        free(outgoing);

        return NULL;
}

NDhcp4Header *n_dhcp4_outgoing_get_header(NDhcp4Outgoing *outgoing) {
        return &outgoing->message->header;
}

size_t n_dhcp4_outgoing_get_raw(NDhcp4Outgoing *outgoing, const void **rawp) {
        if (rawp)
                *rawp = outgoing->message;
        return outgoing->n_message;
}

static void n_dhcp4_outgoing_append_option(NDhcp4Outgoing *outgoing, uint8_t option, const void *data, uint8_t n_data) {
        uint8_t *blob = (void *)outgoing->message;

        blob[outgoing->i_message++] = option;
        blob[outgoing->i_message++] = n_data;
        memcpy(blob + outgoing->i_message, data, n_data);
        outgoing->i_message += n_data;
        blob[outgoing->i_message] = N_DHCP4_OPTION_END;
}

int n_dhcp4_outgoing_append(NDhcp4Outgoing *outgoing, uint8_t option, const void *data, uint8_t n_data) {
        NDhcp4Message *m;
        size_t rem, n;
        uint8_t overload;

        assert(option != N_DHCP4_OPTION_PAD);
        assert(option != N_DHCP4_OPTION_END);
        assert(option != N_DHCP4_OPTION_OVERLOAD);

        /*
         * If the iterator is on the OPTIONs field, try appending the new blob.
         * We need 2 header-bytes plus @n_data bytes. Additionally, we always
         * reserve 3 trailing bytes for a possible OVERLOAD option, and 1 byte
         * for the END marker.
         */
        if (outgoing->i_message >= offsetof(NDhcp4Message, options)) {
                rem = outgoing->n_message - outgoing->i_message;

                /* try fitting into remaining OPTIONs space */
                if (rem >= n_data + 2U + 3U + 1U) {
                        n_dhcp4_outgoing_append_option(outgoing, option, data, n_data);
                        return 0;
                }

                /* try fitting into allowed OPTIONs space */
                if (outgoing->max_size - outgoing->i_message >= n_data + 2U + 3U + 1U) {
                        /* try over-allocation to reduce allocation pressure */
                        n = MIN(outgoing->max_size,
                                outgoing->n_message + n_data + 128);
                        m = realloc(outgoing->message, n);
                        if (!m)
                                return -ENOMEM;

                        outgoing->message = m;
                        outgoing->n_message = n;
                        n_dhcp4_outgoing_append_option(outgoing, option, data, n_data);
                        return 0;
                }

                /* not enough remaining space, try OVERLOAD */
                if (!outgoing->overload)
                        return -ENOBUFS;

                overload = outgoing->overload;
                n_dhcp4_outgoing_append_option(outgoing, N_DHCP4_OPTION_OVERLOAD, &overload, 1);

                if (overload & N_DHCP4_OVERLOAD_FILE)
                        outgoing->message->file[0] = N_DHCP4_OPTION_END;
                if (overload & N_DHCP4_OVERLOAD_SNAME)
                        outgoing->message->sname[0] = N_DHCP4_OPTION_END;

                if (overload & N_DHCP4_OVERLOAD_FILE)
                        outgoing->i_message = offsetof(NDhcp4Message, file);
                else if (overload & N_DHCP4_OVERLOAD_SNAME)
                        outgoing->i_message = offsetof(NDhcp4Message, sname);
        }

        /*
         * The OPTIONs section is full and OVERLOAD was enabled. Try writing
         * into the FILE section. Always reserve 1 byte for the trailing END
         * marker.
         */
        if (outgoing->i_message >= offsetof(NDhcp4Message, file)) {
                rem = sizeof(outgoing->message->file);
                rem -= outgoing->i_message - offsetof(NDhcp4Message, file);

                if (rem >= n_data + 2U + 1U) {
                        n_dhcp4_outgoing_append_option(outgoing, option, data, n_data);
                        return 0;
                }

                if (overload & N_DHCP4_OVERLOAD_SNAME)
                        outgoing->i_message = offsetof(NDhcp4Message, sname);
                else
                        return -ENOBUFS;
        }

        /*
         * OPTIONs and FILE are full, try putting data into the SNAME section
         * as a last resort.
         */
        if (outgoing->i_message >= offsetof(NDhcp4Message, sname)) {
                rem = sizeof(outgoing->message->sname);
                rem -= outgoing->i_message - offsetof(NDhcp4Message, sname);

                if (rem >= n_data + 2U + 1U) {
                        n_dhcp4_outgoing_append_option(outgoing, option, data, n_data);
                        return 0;
                }
        }

        return -ENOBUFS;
}

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

        overload = 0;
        m = (uint8_t *)&incoming->message;
        offset = incoming->n_message;

        /*
         * Linearize all OPTIONs of the incoming message. We know that
         * @incoming->message is preallocated to be big enough to hold the
         * entire linearized message _trailing_ the original copy. All we have
         * to do is walk the raw message in @incoming->message and for each
         * option we find, copy it into the trailing space, concatenating all
         * instances we find.
         */

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

                        if (!incoming->options[o].value) {
                                n_dhcp4_incoming_merge(incoming, &offset, overload, o);

                                /* fetch OVERLOAD value if we just parsed it */
                                if (o == N_DHCP4_OPTION_OVERLOAD && incoming->options[o].size == 1)
                                        overload = *incoming->options[o].value;
                        }

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
