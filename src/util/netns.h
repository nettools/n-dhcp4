#pragma once

/*
 * Network Namespaces
 *
 * XXX
 */

#include <stdlib.h>

void netns_get(int *netnsp);
void netns_set(int netns);
void netns_new(int *netnsp);

void netns_pin(int netns, const char *name);
void netns_unpin(const char *name);
