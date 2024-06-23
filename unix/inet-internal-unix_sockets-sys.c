/*****************************************************************************
**                                                                          **
**                    Internet Protocol Suite Package                       **
**                                                                          **
** ************************************************************************ **
**                                                                          **
**  Copyright (C) 2020-2023, ANNEXI-STRAYLINE Inc.                          **
**  All rights reserved.                                                    **
**                                                                          **
**  Original Contributors:                                                  **
**  * Ensi Martini (ANNEXI-STRAYLINE)                                       **
**  * Richard Wai  (ANNEXI-STRAYLINE)                                       **
**                                                                          **
**  Redistribution and use in source and binary forms, with or without      **
**  modification, are permitted provided that the following conditions are  **
**  met:                                                                    **
**                                                                          **
**      * Redistributions of source code must retain the above copyright    **
**        notice, this list of conditions and the following disclaimer.     **
**                                                                          **
**      * Redistributions in binary form must reproduce the above copyright **
**        notice, this list of conditions and the following disclaimer in   **
**        the documentation and/or other materials provided with the        **
**        distribution.                                                     **
**                                                                          **
**      * Neither the name of the copyright holder nor the names of its     **
**        contributors may be used to endorse or promote products derived   **
**        from this software without specific prior written permission.     **
**                                                                          **
**  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS     **
**  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT       **
**  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A **
**  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      **
**  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   **
**  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT        **
**  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   **
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY   **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT     **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE   **
**  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.    **
**                                                                          **
*****************************************************************************/

#ifdef __INET_OS_LINUX
#define _GNU_SOURCE
#endif

#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Operation_Status Position Values */
#define OPSTAT_OK                 0
#define OPSTAT_NOT_READY          1
#define OPSTAT_TIMEDOUT           2
#define OPSTAT_NOT_CONNECTED      3
#define OPSTAT_CONNECTION_RESET   4
#define OPSTAT_CONNECTION_REFUSED 5
#define OPSTAT_NET_UNREACHABLE    6
#define OPSTAT_HOST_UNREACHABLE   7
#define OPSTAT_UNAUTHORIZED       8
#define OPSTAT_ADDRESS_OCCUPIED   9
#define OPSTAT_OTHER_FAILURE      10

void __inet_internal_unix_sockets_sys_convert_errno
(int * status_pos, int * errno_out)
{
     *errno_out = errno;

     switch (*errno_out)
     {

     case EAGAIN:
          *status_pos = OPSTAT_NOT_READY;
          break;

     case ETIMEDOUT:
          *status_pos = OPSTAT_TIMEDOUT;
          break;

     case ECONNRESET:
          *status_pos = OPSTAT_CONNECTION_RESET;
          break;

     case ECONNREFUSED:
          *status_pos = OPSTAT_CONNECTION_REFUSED;
          break;

     case ENETUNREACH:
     case EADDRNOTAVAIL:
          *status_pos = OPSTAT_NET_UNREACHABLE;
          break;
          
     case EHOSTUNREACH:
          *status_pos = OPSTAT_HOST_UNREACHABLE;
          break;

     case EADDRINUSE:
          *status_pos = OPSTAT_ADDRESS_OCCUPIED;
          break;

     case EACCES:
          *status_pos = OPSTAT_UNAUTHORIZED;
          break;
          
     default:
          *status_pos = OPSTAT_OTHER_FAILURE;
          break;
     }

}

int __inet_internal_unix_sockets_sys_set_nonblocking (int fd )
{
     return ( fcntl ( fd, F_SETFL, fcntl ( fd, F_GETFL, 0 ) | O_NONBLOCK ) );
}

static void set_in4_addr
(struct sockaddr_in * name, struct in_addr * addr, in_port_t port)
{
     const socklen_t size = sizeof ( struct sockaddr_in );
     
     bzero ( name, size );
#ifdef __INET_OS_BSD
     name->sin_len    = size;
#endif
     name->sin_family = PF_INET;
     name->sin_port   = htons ( port );
     name->sin_addr   = *addr;
}

static void set_in6_addr
(struct sockaddr_in6 * name, struct in6_addr * addr, in_port_t port)
{
     const socklen_t size = sizeof ( struct sockaddr_in6 );
     
     bzero ( name, size );
#ifdef __INET_OS_BSD
     name->sin6_len    = size;
#endif
     name->sin6_family = PF_INET6;
     name->sin6_port   = htons ( port );
     name->sin6_addr   = *addr;
}

int __inet_internal_unix_sockets_sys_do_connect4
(int s, struct in_addr * addr, in_port_t port)
{
     struct sockaddr_in name;
     
     set_in4_addr ( &name, addr, port );

     return connect ( s, (struct sockaddr *)&name, sizeof name );
}

int __inet_internal_unix_sockets_sys_do_connect6
(int s, struct in6_addr * addr, in_port_t port)
{
     struct sockaddr_in6 name;
     
     set_in6_addr ( &name, addr, port );

     return connect ( s, (struct sockaddr *)&name, sizeof name );
}

int __inet_internal_unix_sockets_sys_do_bind4
(int s, struct in_addr * addr, in_port_t port)
{
     struct sockaddr_in name;

     set_in4_addr ( &name, addr, port );

     return bind ( s, (struct sockaddr *)&name, sizeof name );
     
}

int __inet_internal_unix_sockets_sys_do_bind6
(int s, struct in6_addr * addr, in_port_t port)
{
     struct sockaddr_in6 name;

     set_in6_addr ( &name, addr, port );

     return bind ( s, (struct sockaddr *)&name, sizeof name );
     
}

void __inet_internal_unix_sockets_sys_do_accept
(int ls, int * cs, in_port_t * port,
 struct in_addr * addr4, struct in6_addr * addr6, int * ipver)
{
     struct sockaddr_in6  name6;
     struct sockaddr_in * name4 = (struct sockaddr_in *)&name6;
     socklen_t addrlen = sizeof name6;
     int retval;

     bzero ( &name6, (size_t)addrlen );

#ifdef __INET_OS_DARWIN
     /* MacOS/iOS/etc still doesn't have accept4! */
     *cs = accept ( ls, (struct sockaddr *)&name6, &addrlen );
#else
     *cs = accept4 ( ls, (struct sockaddr *)&name6, &addrlen, SOCK_CLOEXEC );
#endif

     if ( *cs < 0 ) return;

     /* Extract the right address */
     
     if ( addrlen == sizeof ( struct sockaddr_in ) )
     {
          /* IPv4 */
          *ipver = 4;
          *addr4 = name4->sin_addr;
          *port  = ntohs ( name4->sin_port );
          
     }
     else if ( addrlen == sizeof name6 )
     {
          /* IPv6 */
          *ipver = 6;
          *addr6 = name6.sin6_addr;
          *port  = ntohs ( name6.sin6_port );
     }
     else
     {
          *ipver = -1;
          bzero ( &name6, sizeof name6 );
     }

}

int __inet_internal_unix_sockets_sys_do_poll
( const int * fds, int fd_count, short events,
  int no_timeout, const struct timespec * timeout )
{
     struct pollfd pfds[fd_count];

     pfds[0].fd      = fds[0];
     pfds[0].events  = events;
     pfds[0].revents = events;

     if ( fd_count > 1 )
     {
          pfds[1].fd      = fds[1];
          pfds[1].events  = events;
          pfds[1].revents = events;
     }

     /* MacOS/iOS/etc doesn't have ppoll! */
#ifdef __INET_OS_DARWIN
     return
          (poll (pfds, (nfds_t)fd_count,
                 /* Compute miliseconds timeout for poll(2) */
                 (no_timeout > 0 ? -1:
                  (int)
                  ((timeout->tv_sec  * 1000) +               /* 1000    ms/s  */
                   (time_t)(timeout->tv_nsec / 1000000))))); /* 1000000 ns/ms */
#else
     return (ppoll ( pfds, (nfds_t)fd_count,
                     (no_timeout > 0 ? NULL : timeout), NULL ));
     
#endif
     
}


void __inet_internal_unix_sockets_sys_block_sigpipe ( void )
{
     signal ( SIGPIPE, SIG_IGN );
}
