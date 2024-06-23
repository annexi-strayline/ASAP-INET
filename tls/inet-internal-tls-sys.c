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

#include <tls.h>
#include <stdint.h>

/* For cryptographic randomness */
#ifdef __INET_OS_LINUX
#include <sys/random.h>
#else
#include <stdlib.h>
#endif

const ssize_t __inet_internal_tls_sys_TLS_WANT_POLLIN  = TLS_WANT_POLLIN;
const ssize_t __inet_internal_tls_sys_TLS_WANT_POLLOUT = TLS_WANT_POLLOUT;

const uint32_t
__inet_internal_tls_sys_TLS_PROTOCOL_TLSv1_0 = TLS_PROTOCOL_TLSv1_0;

const uint32_t
__inet_internal_tls_sys_TLS_PROTOCOL_TLSv1_1 = TLS_PROTOCOL_TLSv1_1;

const uint32_t
__inet_internal_tls_sys_TLS_PROTOCOL_TLSv1_2 = TLS_PROTOCOL_TLSv1_2;

const uint32_t
__inet_internal_tls_sys_TLS_PROTOCOL_TLSv1_3 = TLS_PROTOCOL_TLSv1_3;

#ifdef __INET_OS_LINUX
static void linux_random ( void * buf, size_t buflen )
{
     /* Linux always has its own totally different way to do it. */
     /* Meanwhile all BSDs, MacOS, AND Solaris all have the much more */
     /* elegant arc4random */

     /* In the Linux case, we need to actually check to see if a signal */
     /* interrupted our random numbers. Like really? */

     /* Considering that will likely be rare, we'll just retry from */
     /* scratch until we get the whole buffered fill. Otherwise it would */
     /* just be too complicated, which would be more insecure. */

     ssize_t done_len;

     do
     {
          done_len = getrandom ( buf, buflen, 0 );

     } while (done_len != (ssize_t)buflen);
     
}
#endif


void __inet_internal_tls_sys_cryptorand_buffer ( char * buf, size_t len )
{
#ifdef __INET_OS_LINUX
     /* See rant in linux_random above. What a snowflake */
     linux_random ( buf, len );
#else
     arc4random_buf ( buf, len );  /* Easy. Peasy. */
#endif

}

uint32_t __inet_internal_tls_sys_cryptorand_uint32 ( void )
{
#ifdef __INET_OS_LINUX
     /* Ughh.. !!! */
     uint32_t temp;
     linux_random ( &temp, sizeof ( temp ) );
     return ( temp );
#else
     return ( arc4random ( ) ); /* This is what normal people do */
#endif
}



