/*****************************************************************************
**                                                                          **
**                    Internet Protocol Suite Package                       **
**                                                                          **
** ************************************************************************ **
**                                                                          **
**  Copyright (C) 2020-2023, ANNEXI-STRAYLINE Trans-Human Ltd.              **
**  All rights reserved.                                                    **
**                                                                          **
**  Original Contributors:                                                  **
**  * Richard Wai (ANNEXI-STRAYLINE)                                        **
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

#include <poll.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* socklen_t checking */

size_t __inet_internal_os_constants_sys_sizeof_socklen_t ( void )
{
     return sizeof ( socklen_t );
}

/* ssize_t checking */

size_t __inet_internal_os_constants_sys_sizeof_ssize_t ( void )
{
     return sizeof ( ssize_t );
}

/* struct timespec checking */

size_t __inet_internal_os_constants_sys_sizeof_struct_timespec ( void )
{
     return sizeof ( struct timespec );
}

/* Open(2) flags */

const int __inet_internal_os_constants_sys_O_RDWR    = O_RDWR;
const int __inet_internal_os_constants_sys_O_CLOEXEC = O_CLOEXEC;

/* Address Families  */

const int __inet_internal_os_constants_sys_AF_INET   = AF_INET;
const int __inet_internal_os_constants_sys_AF_INET6  = AF_INET6;
const int __inet_internal_os_constants_sys_AF_UNSPEC = AF_UNSPEC;

/* Protocol Families */

const int __inet_internal_os_constants_sys_PF_INET  = PF_INET;
const int __inet_internal_os_constants_sys_PF_INET6 = PF_INET6;

/* -- IPPROTO Values (getaddrinfo) <netinet/in.h> */

const int __inet_internal_os_constants_sys_IPPROTO_TCP  = IPPROTO_TCP;
const int __inet_internal_os_constants_sys_IPPROTO_UDP  = IPPROTO_UDP;
const int __inet_internal_os_constants_sys_IPPROTO_SCTP = IPPROTO_SCTP;

/* Socket Types and Options */

/* For MacOS, SOCK_NONBLOCK is not explicitly defined, and the socket(2)    */
/* manpage also doesn't give any suggestion that flags can be used with the */
/* type argument of socket(2)                                               */

/* Note that we don't actually use SOCK_NONBLOCK on MacOS                   */

#ifndef SOCK_NONBLOCK
# define SOCK_NONBLOCK O_NONBLOCK
#endif

/* Same is true for MacOS vis-a-vis SOCK_CLOEXEC, which is used             */

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC O_CLOEXEC
#endif

const int __inet_internal_os_constants_sys_SOCK_STREAM    = SOCK_STREAM;
const int __inet_internal_os_constants_sys_SOCK_DGRAM     = SOCK_DGRAM;
const int __inet_internal_os_constants_sys_SOCK_SEQPACKET = SOCK_SEQPACKET;
const int __inet_internal_os_constants_sys_SOCK_CLOEXEC   = SOCK_CLOEXEC;
const int __inet_internal_os_constants_sys_SOCK_NONBLOCK  = SOCK_NONBLOCK;
const int __inet_internal_os_constants_sys_SOL_SOCKET     = SOL_SOCKET;

/* Message flags */

const int __inet_internal_os_constants_sys_MSG_PEEK     = MSG_PEEK;
const int __inet_internal_os_constants_sys_MSG_NOSIGNAL = MSG_NOSIGNAL;

/* Shutdown "hows" */

const int __inet_internal_os_constants_sys_SHUT_RD   = SHUT_RD;
const int __inet_internal_os_constants_sys_SHUT_WR   = SHUT_WR;
const int __inet_internal_os_constants_sys_SHUT_RDWR = SHUT_RDWR;

/* Polling  */

const short __inet_internal_os_constants_sys_POLLIN  = POLLIN;
const short __inet_internal_os_constants_sys_POLLOUT = POLLOUT;

/* getaddrinfo flags <netdb.h> */

const int __inet_internal_os_constants_sys_AI_ADDRCONFIG = AI_ADDRCONFIG;
const int __inet_internal_os_constants_sys_AI_CANONNAME  = AI_CANONNAME;

/* Get_Errno */

int __inet_internal_os_constants_sys_get_errno ( void )
{
     return errno;
}
