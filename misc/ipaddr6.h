/**
 * @file ipaddr6.h
 * @author Ambroz Bizjak <ambrop7@gmail.com>, Jaka Hudoklin <jakahudoklin@gmail.com>
 * 
 * @section LICENSE
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * @section DESCRIPTION
 * 
 * IPv6 address parsing functions.
 */

#ifndef BADVPN_MISC_IPADDR6_H
#define BADVPN_MISC_IPADDR6_H

#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <misc/debug.h>
#include <misc/parse_number.h>

// from /etc/iproute2/rt_scopes
#define IPADDR6_SCOPE_GLOBAL 0
#define IPADDR6_SCOPE_HOST 254
#define IPADDR6_SCOPE_LINK 253
#define IPADDR6_SCOPE_SITE 200

struct ipv6_ifaddr {
    uint8_t addr[16];
    int prefix;
    int scope;
};

#define IPADDR6_PRINT_MAX INET6_ADDRSTRLEN

static int ipaddr6_print_addr (const uint8_t *addr, char *out_buf) WARN_UNUSED;
static int ipaddr_parse_ipv6_addr_bin (char *name, size_t name_len, uint8_t *out_addr);
static int ipaddr_parse_ipv6_addr (char *name, uint8_t *out_addr);
static int ipaddr_parse_ipv6_prefix_bin (char *str, size_t str_len, int *num);
static int ipaddr_parse_ipv6_prefix (char *str, int *num);
static int ipaddr_parse_ipv6_ifaddr (char *str, struct ipv6_ifaddr *out);
static void ipaddr_ipv6_mask_from_prefix (int prefix, uint8_t *mask);
static int ipaddr_ipv6_addrs_in_network (uint8_t *addr1, uint8_t *addr2, int netprefix);

int ipaddr6_print_addr (const uint8_t *addr, char *out_buf)
{
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_port = 0;
    a.sin6_flowinfo= 0;
    memcpy(a.sin6_addr.s6_addr, addr, 16);
    a.sin6_scope_id = 0;
    
    if (getnameinfo((struct sockaddr *)&a, sizeof(a), out_buf, IPADDR6_PRINT_MAX, NULL, 0, NI_NUMERICHOST) < 0) {
        return 0;
    }
    
    return 1;
}

int ipaddr_parse_ipv6_addr_bin (char *name, size_t name_len, uint8_t *out_addr)
{
   struct in6_addr result;
   char local[INET6_ADDRSTRLEN];

   if(name_len > sizeof(local) - 1) {
       return 0;
   }
   memcpy(local, name, name_len);
   local[name_len] = '\0';

   if (inet_pton(AF_INET6, local, &result) != 1) {
       return 0;
   }

   memcpy(out_addr, result.s6_addr, 16);
   return 1;
}

int ipaddr_parse_ipv6_addr (char *name, uint8_t *out_addr)
{
    return ipaddr_parse_ipv6_addr_bin(name, strlen(name), out_addr);
}

int ipaddr_parse_ipv6_prefix_bin (char *str, size_t str_len, int *num)
{
    uintmax_t d;
    if (!parse_unsigned_integer_bin(str, str_len, &d)) {
        return 0;
    }
    if (d > 128) {
        return 0;
    }
    
    *num = d;
    return 1;
}

int ipaddr_parse_ipv6_prefix (char *str, int *num)
{
    return ipaddr_parse_ipv6_prefix_bin(str, strlen(str), num);
}

int ipaddr_parse_ipv6_ifaddr (char *str, struct ipv6_ifaddr *out)
{
    char *slash = strstr(str, "/");
    if (!slash) {
        return 0;
    }
    
    if (!ipaddr_parse_ipv6_addr_bin(str, (slash - str), out->addr)) {
        return 0;
    }
    
    if (!ipaddr_parse_ipv6_prefix(slash + 1, &out->prefix)) {
        return 0;
    }
    
    return 1;
}

void ipaddr_ipv6_mask_from_prefix (int prefix, uint8_t *mask)
{
   ASSERT(prefix >= 0)
   ASSERT(prefix <= 128)

   int quot = prefix / 8;
   int rem = prefix % 8;

   // set bytes with all bits set
   memset(mask, 0xff, quot);

   // clear the remaining bytes
   memset(mask + quot, 0, 16 - quot);

   // fix partial byte
   for (int i = 0; i < rem; i++) {
       mask[quot] |= 1 << (8 - i - 1);
   }
}

int ipaddr_ipv6_addrs_in_network (uint8_t *addr1, uint8_t *addr2, int netprefix)
{
   ASSERT(netprefix >= 0)
   ASSERT(netprefix <= 128)

   // check bytes which fall completely inside the prefix
   int quot = netprefix / 8;
   if (memcmp(addr1, addr2, quot)) {
       return 0;
   }

   // no remaining bits to check?
   if (netprefix % 8 == 0) {
       return 1;
   }

   // check remaining bits
   uint8_t t = 0;
   for (int i = 0; i < netprefix % 8; i++) {
       t |= 1 << (8 - i - 1);
   }
   return ((addr1[quot] & t) == (addr2[quot] & t));
}

#endif
