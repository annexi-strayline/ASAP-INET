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

-- This package provides facilities for querying hosts base on their host name.

private with System.Address_To_Access_Conversions;

private with Ada.Finalization;
private with Interfaces.C.Strings;

package INET.IP.Lookup is
   
   type IP_Protocols is (Proto_Any, Proto_TCP, Proto_UDP, Proto_SCTP);
   
   type IP_Lookup_Entry is
      record
         Protocol: IP_Protocols;
         Address : IP_Address;
      end record;
   
   type IP_Lookup is tagged limited private;
   
   procedure Lookup (List     : in out IP_Lookup;
                     Host_Name: in     String;
                     Protocol : in     IP_Protocols := Proto_Any)
   with Pre'Class => Host_Name'Length > 0;
   
   procedure Lookup (List     : in out IP_Lookup;
                     Host_Name: in     String;
                     Protocol : in     IP_Protocols := Proto_Any;
                     Version  : in     IP_Version)
   with Pre'Class => Host_Name'Length > 0;
   
   -- Executes a lookup of Host_Name. If the lookup fails, List will be
   -- empty, and thus Has_More_Entries will return False immediately,
   -- otherwise, List will be populated with all entries that meet the
   -- filtering parameters, if any.
   --
   -- If Host_Name is empty, Constraint_Error is raised.
   --
   -- If List has been invoked previously, it is cleared (finalized).
   --
   -- If Protocol or Version is specified, lookup results are restricted
   -- to those protocols and/or that IP version. If not specified, any
   -- version that is reachable is included.
   --
   -- Lookup does not propagate exceptions.
   
   function Has_More_Entries (List: IP_Lookup) return Boolean;
   
   -- Returns True iff there are more entries on the lookup list
   
   function Canonical_Name (List: IP_Lookup) return String;
   
   -- Returns the canonical name (CNAME) of the specified Host_Name, 
   -- but only if the Lookup was successful. If the lookup was not successful,
   -- an empty String is returned. For lookups without a canonical name, the
   -- returned String should be equivalent to Host_Name, but this is an
   -- operating-system behaviour, and is not checked by this implementation.
   
   function  Pop (List: in out IP_Lookup) return IP_Lookup_Entry with
     Pre'Class => List.Has_More_Entries;
   
   procedure Pop (List: in out IP_Lookup; Item: out IP_Lookup_Entry) 
   with Pre'Class => List.Has_More_Entries;
   
   -- Returns the next available entry in the lookup list. If Lookup does not
   -- have more entires in the lookup, Constraint_Error is raised.
   
   procedure Iterate 
     (List  : in out IP_Lookup;
      Action: not null access procedure (Item: in IP_Lookup_Entry));
   
   -- Pops each entry from List, and passes it into a call to Action, until
   -- all entries have been popped.
   --
   -- If there are no entries an call to Iterate, Action is never invoked, and
   -- nothing happens.
   
private
   
   type addrinfo;  -- Taft amendment type in the wild!
   type Entry_Pointer is access all addrinfo with 
     Storage_Size => 0, Convention => C;
   
   use type Interfaces.C.Strings.chars_ptr;
   Null_Chars_Ptr: Interfaces.C.Strings.chars_ptr 
     renames Interfaces.C.Strings.Null_Ptr;
   
   type IP_Lookup is new Ada.Finalization.Limited_Controlled with
      record
         List_Head : Entry_Pointer                 := null;
         Next_Pop  : Entry_Pointer                 := null;
         Canonname: Interfaces.C.Strings.chars_ptr := Null_Chars_Ptr;
      end record;
   
   overriding procedure Finalize (List: in out IP_Lookup);
   -- Dealocates the underlying "struct addrinfo" and then default initializes
   -- List
   
end INET.IP.Lookup;
