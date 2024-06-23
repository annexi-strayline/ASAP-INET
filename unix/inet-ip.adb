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
--  * Ensi Martini (ANNEXI-STRAYLINE)                                       --
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

with Interfaces.C;
with Interfaces.C.Strings;
with Ada.Strings.Maps;

with INET.Internal.OS_Constants; use INET.Internal.OS_Constants;

package body INET.IP is
   
   -------------------------
   -- From_String_Address --
   -------------------------
   
   function From_String_Address (Address: String) return IP_Address is
      use Interfaces.C;
      use Ada.Strings.Maps;
      
      function inet4_pton (af  : in     int := AF_INET; 
                           src : in     char_array; 
                           dst :    out IPv4_Address)
                          return int
      with 
        Convention    => C,
        Import        => True,
        External_Name => "inet_pton";
      
      function inet6_pton (af  : in     int := AF_INET6; 
                           src : in     char_array; 
                           dst :    out IPv6_Address)
                          return int
      with 
        Convention    => C,
        Import        => True,
        External_Name => "inet_pton";


      Legal_Decimal : Character_Set := To_Set ("0123456789");
      Legal_Hex     : Character_Set := Legal_Decimal or To_Set ("abcdefABCDEF");

      Legal_IPv4    : Character_Set := Legal_Decimal or To_Set (".");
      Legal_IPv6    : Character_Set := Legal_Hex     or To_Set (":");

      -- Legal_Characters : Character_Set := To_Set ("0123456789abcdefABCDEF:.");
      -- Legal_IPv46      : Character_Set := Legal_IPv4 and Legal_IPv6;
      
      Retval     : int;
      IPv4_Valid : Boolean := True;
      IPv6_Valid : Boolean := True;
      
      pragma Assertion_Policy (Check);
   begin

      -- We first check the legality of the address provided
      for C of Address loop
         
         IPv4_Valid := IPv4_Valid and Is_In(Element => C,
                                            Set     => Legal_IPv4);
      
         IPv6_Valid := IPv6_Valid and Is_In(Element => C,
                                            Set     => Legal_IPv6);
         
         exit when not (IPv4_Valid or IPv6_Valid);

      end loop;

      -- It will never be the case that an address fulfills requirements for
      -- both IPv4 and IPv6, so we can directly check each individually
      
      if IPv4_Valid then

         return A: IP_Address (Version => IPv4) do
            Retval := inet4_pton (src => To_C (Address),
                                  dst => A.v4_Address);
            
            if Retval /= 1 then
               raise Invalid_Address;
            end if;
         end return;

      elsif IPv6_Valid then

         return A: IP_Address (Version => IPv6) do
            Retval := inet6_pton (src => To_C (Address),
                                  dst => A.v6_Address);
            
            if Retval /= 1 then
               raise Invalid_Address;
            end if;
         end return;

      else
         raise Invalid_Address;
      end if;
      
   end From_String_Address;
   
   -----------------------
   -- To_String_Address --
   -----------------------
   
   function To_String_Address (Address: IP_Address) return String is
      use Interfaces.C;
      use Interfaces.C.Strings;
      -- Address is in network byte order

      function inet4_ntop (af   : in     int := AF_INET;
                           src  : in     IPv4_Address;
                           dst  :    out Interfaces.C.Char_Array;
                           size : in     socklen_t)
                          return Interfaces.C.Strings.chars_ptr
      with
         Convention    => C,
         Import        => True,
         External_Name => "inet_ntop";

      function inet6_ntop (af   : in     int := AF_INET6;
                           src  : in     IPv6_Address;
                           dst  :    out Interfaces.C.Char_Array;
                           size : in     socklen_t)
                          return Interfaces.C.Strings.chars_ptr
      with
         Convention    => C,
         Import        => True,
         External_Name => "inet_ntop";
      

      -- Output_IPv* is the buffer to which the dst out address will be written
      -- Output_IPv* contains one additional position for the null terminator
      -- The longest possible IPv4 will be 16 bytes long
      -- The longest possible IPv6 will be 46 bytes long
      -- Since we are only returning one string, we can just take the longest
      -- possible array size and use that for the output
      Retval: Interfaces.C.Strings.chars_ptr;

      Address_Buffer: Interfaces.C.Char_Array(1 .. 40);
      -- Based on the longest-possible IPv6 address, which is eight groups
      -- of four hex digits (32), separated by colons (7), with room for a null
      -- terminator = 32 + 7 + 1  = 40

   begin
      
      case Address.Version is
         when IPv4 =>
            Retval := inet4_ntop(src  => Address.v4_Address,
                                 dst  => Address_Buffer,
                                 size => Address_Buffer'Length);
            
         when IPv6 => 
            Retval := inet6_ntop(src  => Address.v6_Address,
                                 dst  => Address_Buffer,
                                 size => Address_Buffer'Length);
      end case;
      
      
      if Retval = Interfaces.C.Strings.Null_Ptr then
         raise Invalid_Address;

      else
         return To_Ada (Address_Buffer);

      end if;

   end To_String_Address;

end INET.IP;
