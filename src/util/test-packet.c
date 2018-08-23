/*
 * Test for raw packet utility library
 */

#include <stdio.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include "packet.h"
#include "../test.h"

typedef struct Blob {
        uint16_t checksum;
        uint8_t data[128];
} Blob;

static void test_checksum_one(Blob *blob, size_t size) {
        uint16_t checksum;

        blob->checksum = 0;
        blob->checksum = packet_internet_checksum((uint8_t*)blob, size);

        checksum = packet_internet_checksum((uint8_t*)blob, size);
        assert(!checksum);
}

static void test_checksum(void) {
        Blob blob = {};

        for (size_t i = 0; i < sizeof(blob.data); ++i)
                blob.data[i] = (i & 0xffff) ^ (i << 16);

        for (size_t j = 0; j < sizeof(uint64_t); ++j) {
                for (uint32_t i = 0; i <= 0xffff; ++i) {
                        blob.data[0] = i & 0xff;
                        blob.data[1] = i >> 8;
                        test_checksum_one(&blob, sizeof(blob) - j);
                }
        }
}

static void test_checksum_udp_one(Blob *blob, size_t size) {
        uint16_t checksum;

        checksum = packet_internet_checksum_udp(&(struct in_addr){10<<24 | 2}, &(struct in_addr){10<<24 | 1},
                                                67, 68, blob->data, sizeof(blob->data), 0) ?: 0xffff;
        checksum = packet_internet_checksum_udp(&(struct in_addr){10<<24 | 2}, &(struct in_addr){10<<24 | 1},
                                                67, 68, blob->data, sizeof(blob->data), checksum);
        assert(!checksum);
}

static void test_checksum_udp(void) {
        Blob blob = {};

        for (size_t i = 0; i < sizeof(blob.data); ++i)
                blob.data[i] = (i & 0xffff) ^ (i << 16);

        for (size_t j = 0; j < sizeof(uint64_t); ++j) {
                for (uint32_t i = 0; i <= 0xffff; ++i) {
                        blob.data[0] = i & 0xff;
                        blob.data[1] = i >> 8;
                        test_checksum_udp_one(&blob, sizeof(blob) - j);
                }
        }
}

int main(int argc, char **argv) {
        test_checksum();
        test_checksum_udp();
}
