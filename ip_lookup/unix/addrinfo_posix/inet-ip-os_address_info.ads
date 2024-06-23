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

-- This package contains the os-specific layout of the "addrinfo" (netdb.h)
-- structure

-- This is the POSIX version (as in the ordering of the struct "follows" the 
-- order given - not specified - by the POSIX spec for netdb.h, where ai_addr
-- preceeds ai_canonname).
--
-- This applies to Linux, Darwin, and OpenBSD

with Interfaces.C;            use Interfaces.C;
with Interfaces.C.Strings;    use Interfaces.C.Strings;
with System.Storage_Elements;

with INET.Internal.OS_Constants;

private package INET.IP.OS_Address_Info is
   
   subtype socklen_t is Internal.OS_Constants.socklen_t;
   
   Null_Chars_Ptr: Strings.chars_ptr renames Strings.Null_Ptr;
   
   type Void_Pointer is access System.Storage_Elements.Storage_Element with 
     Storage_Size => 0, Convention => C;
   
   type struct_addrinfo;
   type addrinfo_ptr is access struct_addrinfo with
     Storage_Size => 0, Convention => C;

   -- struct addrinfo - getaddrinfo(3) (POSIX) <netdb.h>

   type struct_addrinfo is
      record
         ai_flags    : int               := 0;
         ai_family   : int               := 0;
         ai_socktype : int               := 0;
         ai_protocol : int               := 0;
         ai_addrlen  : socklen_t         := 0;
         ai_addr     : Void_Pointer      := null;
         ai_canonname: Strings.chars_ptr := Null_Chars_Ptr;
         ai_next     : addrinfo_ptr      := null;
      end record
   with Convention => C;
   
end INET.IP.OS_Address_Info;
