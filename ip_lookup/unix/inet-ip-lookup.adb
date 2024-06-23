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

with System.Storage_Elements;
with Interfaces.C;               use Interfaces.C;
with Interfaces.C.Pointers;
with Ada.Unchecked_Conversion;

with INET.IP.OS_Address_Info;
with INET.Internal.OS_Constants; use INET.Internal.OS_Constants;

pragma External_With ("inet-ip-lookup-sys.c");

package body INET.IP.Lookup is
   
   IPv4_addrlen: constant socklen_t with Import => True, Convention => C,
       External_Name => "__inet_ip_lookup_sys_addrlen4";
   
   IPv6_addrlen: constant socklen_t with Import => True, Convention => C,
       External_Name => "__inet_ip_lookup_sys_addrlen6";
   
   package SSE renames System.Storage_Elements;
   use type SSE.Integer_Address;
   
   type addrinfo is new INET.IP.OS_Address_Info.struct_addrinfo with
     Convention => C;
   -- ^ Taft amendment completion
   
   -----------------------
   -- Assert_Constraint --
   -----------------------
   
   procedure Assert_Constraint (Check : in Boolean; Message: in String) with
     Inline is
   begin
      if not Check then
         raise Constraint_Error with Message;
      end if;
   end Assert_Constraint;
   
   ------------
   -- Lookup --
   ------------
   
   procedure Lookup_Actual (List       : in out IP_Lookup;
                            Host_Name  : in     String;
                            Protocol   : in     IP_Protocols := Proto_Any;
                            Version    : in     IP_Version;
                            Any_Version: in     Boolean)
   with Inline is
      use Interfaces.C.Strings;
      
      -- Any_Version ignores the value of Version
      
      function getaddrinfo (hostname: in     char_array;
                            servname: in     chars_ptr := Null_Chars_Ptr;
                            hints   : in     addrinfo;
                            res     :    out Entry_Pointer)
                           return int
      with Import => True, Convention => C, External_Name => "getaddrinfo";
      
      hints: addrinfo;
      Retval: int;
   begin
      if Host_Name'Length = 0 then
         raise Constraint_Error with "Host_Name is an empty String";
      end if;
      
      List.Finalize;  -- Ensure any previous lookups are freed
      
      -- Set-up hints
      hints.ai_flags := AI_CANONNAME;
      
      if Any_Version then
         hints.ai_flags  := hints.ai_flags + AI_ADDRCONFIG;
         hints.ai_family := AF_UNSPEC;
      else
         hints.ai_family := (case Version is 
                                when IPv4 => AF_INET,
                                when IPv6 => AF_INET6);
      end if;
      
      case Protocol is
         when Proto_Any =>
            null; -- defaults are correct
            
         when Proto_TCP =>
            hints.ai_socktype := SOCK_STREAM;
            hints.ai_protocol := IPPROTO_TCP;
            
         when Proto_UDP =>
            hints.ai_socktype := SOCK_DGRAM;
            hints.ai_protocol := IPPROTO_UDP;
            
         when Proto_SCTP =>
            hints.ai_socktype := SOCK_SEQPACKET;
            hints.ai_protocol := IPPROTO_SCTP;
      end case;
      
      Retval := getaddrinfo (hostname => To_C (Host_Name),
                             hints    => hints,
                             res      => List.List_Head);
      
      if Retval /= 0 then
         List.Finalize;
         return;
      end if;
      
      List.Next_Pop  := List.List_Head;
      List.Canonname := List.List_Head.ai_canonname;
      
   end Lookup_Actual;
   
   ----------------------------------------------------------------------
   
   procedure Lookup (List     : in out IP_Lookup;
                     Host_Name: in     String;
                     Protocol : in     IP_Protocols := Proto_Any)
   is begin
      Lookup_Actual (List, Host_Name, Protocol, 
                     Version     => IPv6, -- This is arbitrary (ignored)
                     Any_Version => True);
   end Lookup;
   
   ----------------------------------------------------------------------
   
   procedure Lookup (List     : in out IP_Lookup;
                     Host_Name: in     String;
                     Protocol : in     IP_Protocols := Proto_Any;
                     Version  : in     IP_Version)
   is begin
      Lookup_Actual (List, Host_Name, Protocol, Version,
                     Any_Version => False);
   end Lookup;
   
   ----------------------
   -- Has_More_Entries --
   ----------------------
   
   function Has_More_Entries (List: IP_Lookup) return Boolean is
     (List.Next_Pop /= null);
   
   --------------------
   -- Canonical_Name --
   --------------------
   
   function Canonical_Name (List: IP_Lookup) return String is
      use Interfaces.C.Strings;
   begin
      if List.Canonname = Null_Chars_Ptr then
         return "";
      else
         return Value (List.Canonname);
      end if;
   end Canonical_Name;
   
   ---------
   -- Pop --
   ---------
   
   procedure Pop (List: in out IP_Lookup; Item: out IP_Lookup_Entry) is
      
      subtype Void_Pointer is OS_Address_Info.Void_Pointer;
      
      procedure extract4 (src: in Void_Pointer; addr: out IPv4_Address) with
        Import => True, Convention => C,
        External_Name => "__inet_ip_lookup_sys_extract4";
      
      procedure extract6 (src: in Void_Pointer; addr: out IPv6_Address) with
        Import => True, Convention => C,
        External_Name => "__inet_ip_lookup_sys_extract6";
      
      procedure Advance_List with Inline is
         function To_Entry_Pointer is new Ada.Unchecked_Conversion 
           (Source => OS_Address_Info.addrinfo_ptr,
            Target => Entry_Pointer);
         
         -- This is always safe since Entry_Pointer points at a addrinfo
         -- record, which is a struct_addrinfo
         
      begin
         List.Next_Pop := To_Entry_Pointer (List.Next_Pop.ai_next);
      end;
      
   begin
      
      Assert_Constraint 
        (List.Has_More_Entries, "List has no more entires to pop.");
      pragma Assert (List.Next_Pop /= null);
      
      -- Would have been nice to use case statements here, but unfortunately
      -- we needed to import the C macros as run-time elaborated constants,
      -- and hence they are not static.
         
      if List.Next_Pop.ai_protocol = IPPROTO_TCP then
         Item.Protocol := Proto_TCP;
      elsif List.Next_Pop.ai_protocol = IPPROTO_UDP then
         Item.Protocol := Proto_UDP;
      elsif List.Next_Pop.ai_protocol = IPPROTO_SCTP then
         Item.Protocol := Proto_SCTP;
      else
         -- Ignore unsupported protocols, since the use won't be
         -- able to used them anyways..
         Advance_List;
         return;
      end if;
      
      if List.Next_Pop.ai_family = AF_INET6 then
         Assert_Constraint (List.Next_Pop.ai_addrlen = IPv6_addrlen,
                            "List item address not the exepected size");
         
         Item.Address := (Version => IPv6, others => <>);
         extract6 (src  => List.Next_Pop.ai_addr,
                   addr => Item.Address.v6_Address);
         
      elsif List.Next_Pop.ai_family = AF_INET then
         -- getaddrinfo often mkaes the underlying ai_addr large enough for an
         -- IPv6 address, even if it holds an IPv4 address, so notice how the
         -- check is slightly different
         
         Assert_Constraint (List.Next_Pop.ai_addrlen = IPv4_addrlen,
                            "List item address not the exepected size");
         
         Item.Address := (Version => IPv4, others => <>);
         extract4 (src  => List.Next_Pop.ai_addr,
                   addr => Item.Address.v4_Address);
         
      else
         -- Throw out this item first
         Advance_List;
         raise Constraint_Error with
           "List item address family not recognized";
      end if;
      
      Advance_List;
   end Pop;
   
   ----------------------------------------------------------------------
   
   function Pop (List: in out IP_Lookup) return IP_Lookup_Entry is
   begin
      return Item: IP_Lookup_Entry do
         List.Pop (Item);
      end return;
   end Pop;
   
   -------------
   -- Iterate --
   -------------
   
   procedure Iterate 
     (List  : in out IP_Lookup;
      Action: not null access procedure (Item: in IP_Lookup_Entry))
   is 
      Item: IP_Lookup_Entry;
   begin
      while List.Next_Pop /= null loop
         List.Pop (Item);
         Action (Item);
      end loop;
   end Iterate;
   
   --------------
   -- Finalize --
   --------------
   
   procedure Finalize (List: in out IP_Lookup) is
      procedure freeaddrinfo (ai: Entry_Pointer) with
        Import => True, Convention => C, External_Name => "freeaddrinfo";
   begin
      if List.List_Head /= null then
         freeaddrinfo (List.List_Head);
      end if;
      
      List.List_Head := null;
      List.Next_Pop  := null;
      List.Canonname := Null_Chars_Ptr;
   end Finalize;
   
end INET.IP.Lookup;
