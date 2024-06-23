------------------------------------------------------------------------------
--                                                                          --
--                    Internet Protocol Suite Package                       --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2020, ANNEXI-STRAYLINE Inc.                               --
--  All rights reserved.                                                    --
--                                                                          --
--  Original Contributors:                                                  --
--  * Richard Wai (ANNEXI-STRAYLINE)                                        --
--                                                                          --
--  Redistribution and use in source and binary forms, with or without      --
--  modification, are permitted provided that the following conditions are  --
--  met:                                                                    --
--                                                                          --
--      * Redistributions of source code must retain the above copyright    --
--        notice, this list of conditions and the following disclaimer.     --
--                                                                          --
--      * Redistributions in binary form must reproduce the above copyright --
--        notice, this list of conditions and the following disclaimer in   --
--        the documentation and/or other materials provided with the        --
--        distribution.                                                     --
--                                                                          --
--      * Neither the name of the copyright holder nor the names of its     --
--        contributors may be used to endorse or promote products derived   --
--        from this software without specific prior written permission.     --
--                                                                          --
--  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS     --
--  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT       --
--  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A --
--  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      --
--  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   --
--  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT        --
--  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   --
--  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY   --
--  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT     --
--  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE   --
--  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.    --
--                                                                          --
------------------------------------------------------------------------------

-- This package contains a set of OS-specific constants imported from system
-- header files for use in direct calls to the various system/libc calls

with Interfaces.C; use Interfaces.C;

pragma External_With ("inet-internal-os_constants-sys.c");

package INET.Internal.OS_Constants is
   
   -----------
   -- Types --
   -----------
   
   -- in_port_t --
   
   subtype in_port_t is Interfaces.Unsigned_16;
   
   
   -- socklen_t --
   
   subtype socklen_t is Interfaces.C.unsigned;
   -- POSIX says that socklen_t should be at a minimum a 32-bit unsigned value.
   -- Most libraries apparently misattribute it to an "int". In any case,
   -- we will check this with an assertion pragma, but deviation is probably
   -- very rare
   
   function sizeof_socklen_t return size_t with
     Import => True, Convention => C,
     External_Name => "__inet_internal_os_constants_sys_sizeof_socklen_t";
   
   pragma Assert (Check => sizeof_socklen_t = (socklen_t'Size / 8),
                  Message => "socklen_t is not the expected size. "
                    &        "INET.OS_Constants will need to be modified.");
   
   
   -- ssize_t --
   type ssize_t is new Interfaces.Integer_64;
   
   function sizeof_ssize_t return size_t with
     Import => True, Convention => C,
     External_Name => "__inet_internal_os_constants_sys_sizeof_ssize_t";
   
   pragma Assert (Check => sizeof_ssize_t = (ssize_t'Size / 8),
                  Message => "ssize_t is not the expected size. "
                    &        "INET.OS_Constants will need to be modified.");
   
   -- struct timespec --
   
   -- See <sys/time.h>
   type time_t      is new Interfaces.Integer_64
     with Convention => C;
   -- Most systems will have this as Integer_64. Otherwise they are
   -- susceptible to the Y2038 problem, which at the time of writing,
   -- is "only" 18 years away.
   --
   -- It seems in most cases, it is only i386 that still uses a 32-bit
   -- int. We will have a separate codepath for those cases for the time
   -- being.
   --
   -- Note that the size of time_t will be implicitly checked when
   -- the size of timespec is checked.
   
   -- see clock_gettime(2) - posix
   type timespec is
      record
         tv_sec : time_t;
         tv_nsec: long;
      end record
   with Convention => C;
   
   function sizeof_struct_timespec return size_t with
     Import => True, Convention => C,
     External_Name => "__inet_internal_os_constants_sys_sizeof_struct_timespec";
   
   pragma Assert (Check => sizeof_struct_timespec = (timespec'Size / 8),
                  Message => "struct timespec is not the expected size. "
                    &        "INET.OS_Constants will need to be modified.");
   
   function To_Timespec (T: Duration) return timespec;
   -- Converts an Ada duration value into the corresponding timeval struct
   -- value
   
   ---------------
   -- Constants --
   ---------------
   
   -- Open(2) Flags --
   
   O_RDWR: constant int with Import => True, Convention => C,
       External_Name => "__inet_internal_os_constants_sys_O_RDWR";
   
   O_CLOEXEC: constant int with Import => True, Convention => C,
       External_Name => "__inet_internal_os_constants_sys_O_CLOEXEC";
   
   -- Address Families --
   
   AF_INET: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_AF_INET";
   
   AF_INET6: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_AF_INET6";
   
   AF_UNSPEC: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_AF_UNSPEC";
   
   -- Protocol Families --
   
   PF_INET: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_PF_INET";
   
   PF_INET6: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_PF_INET6";
   
   -- IPPROTO Values (getaddrinfo) <netinet/in.h> --
   
   IPPROTO_TCP: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_IPPROTO_TCP";
   
   IPPROTO_UDP: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_IPPROTO_UDP";
   
   IPPROTO_SCTP: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_IPPROTO_SCTP";
   
   -- Socket Types and Options --
   
   SOCK_STREAM: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_SOCK_STREAM";
   
   SOCK_DGRAM: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_SOCK_DGRAM";
   
   SOCK_SEQPACKET: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_SOCK_SEQPACKET";
   
   SOCK_CLOEXEC: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_SOCK_CLOEXEC";
   
   SOCK_NONBLOCK: constant int with Import => True, Convention => C,
       External_Name => "__inet_internal_os_constants_sys_SOCK_NONBLOCK";
   
   SOL_SOCKET: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_SOL_SOCKET";
   
   -- Message flags --
   
   MSG_PEEK: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_MSG_PEEK";
   
   MSG_NOSIGNAL: constant int with Import => True, Convention => C,
       External_Name => "__inet_internal_os_constants_sys_MSG_NOSIGNAL";
   
   -- Shutdown "hows" --
   
   SHUT_RD: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_SHUT_RD";
   
   SHUT_WR: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_SHUT_WR";
   
   SHUT_RDWR: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_SHUT_RDWR";
   
   -- Polling - poll(2) events flags --
   
   POLLIN : constant short with Import => True, Convention => C,
       External_Name => "__inet_internal_os_constants_sys_POLLIN";
   POLLOUT: constant short with Import => True, Convention => C,
       External_Name => "__inet_internal_os_constants_sys_POLLOUT";
   
   -- getaddrinfo flags <netdb.h> --
   
   AI_ADDRCONFIG: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_AI_ADDRCONFIG";
   
   AI_CANONNAME: constant int with Import => True, Convention => C, 
       External_Name => "__inet_internal_os_constants_sys_AI_CANONNAME";
   
   -- Errno
   
   function Get_Errno return int with Import => True, Convention => C,
     External_Name => "__inet_internal_os_constants_sys_get_errno";
   
end INET.Internal.OS_Constants;
