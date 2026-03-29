// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// See mobile/include/ratls_mobile.h for the canonical version.

#ifndef RATLS_MOBILE_H
#define RATLS_MOBILE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

char *ratls_inspect(const char *host, uint16_t port, const char *ca_cert_path);
char *ratls_verify(const char *host, uint16_t port, const char *ca_cert_path,
                   const char *policy_json);
char *ratls_post(const char *host, uint16_t port, const char *ca_cert_path,
                 const char *path, const char *body);
void ratls_free_string(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* RATLS_MOBILE_H */
