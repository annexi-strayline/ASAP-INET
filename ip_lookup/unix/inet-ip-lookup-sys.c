/*****************************************************************************
**                                                                          **
**                    Internet Protocol Suite Package                       **
**                                                                          **
** ************************************************************************ **
**                                                                          **
**  Copyright (C) 2020, ANNEXI-STRAYLINE Inc.                               **
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

const socklen_t __inet_ip_lookup_sys_addrlen4 = sizeof ( struct sockaddr_in  );
const socklen_t __inet_ip_lookup_sys_addrlen6 = sizeof ( struct sockaddr_in6 );

void __inet_ip_lookup_sys_extract4
( struct sockaddr_in * src, struct in_addr * addr )
{
     *addr = src->sin_addr;
}


void __inet_ip_lookup_sys_extract6
( struct sockaddr_in6 * src, struct in6_addr * addr )
{
     *addr = src->sin6_addr;
}
