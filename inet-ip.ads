------------------------------------------------------------------------------
--                                                                          --
--                    Internet Protocol Suite Package                       --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2020, ANNEXI-STRAYLINE Trans-Human Ltd.                   --
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

package INET.IP is
   Invalid_Address: exception;
   
   type IP_Version is (IPv4, IPv6);
   
   type IPv6_Address is private;
   type IPv4_Address is private;
   
   -- Discriminated 4/6 address
   type IP_Address (Version: IP_Version := IPv6) is
      record
         case Version is
            when IPv4 =>
               v4_Address: IPv4_Address;
            when IPv6 =>
               v6_Address: IPv6_Address;
         end case;
      end record;
   
   
   function From_String_Address (Address: String)     return IP_Address;
   function To_String_Address   (Address: IP_Address) return String;
   
   IPv6_Wildcard: constant IP_Address;  
   IPv4_Wildcard: constant IP_Address; -- INADDR_ANY 
   
private
   type Octet is mod 2**8
     with Size => 8;
   
   -- These values are _always_ in "network order" (big endian).
   -- The most significant octet is always at 'First.
   
   type IPv4_Address is array (1 .. 4)  of aliased Octet with Pack;
   -- 4 x 8bits = 32 bits
   
   type IPv6_Address is array (1 .. 16) of aliased Octet with Pack;
   -- 1 x 16 = 128 bits
   
   IPv6_Wildcard: constant IP_Address := (Version    => IPv6,
                                          v6_Address => (others => 0));
   
   IPv4_Wildcard: constant IP_Address := (Version    => IPv4,
                                          v4_Address => (others => 0));
   
end INET.IP;
