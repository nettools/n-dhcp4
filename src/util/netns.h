#pragma once

/*
 * Network Namespaces
 *
 * The netns utility provides an object-based API to network namespaces. It is
 * meant for testing purposes only.
 */

#include <stdlib.h>

void netns_get(int *netnsp);
void netns_set(int netns);
void netns_set_anonymous(void);
void netns_new(int *netnsp);

void netns_pin(int netns, const char *name);
void netns_unpin(const char *name);
