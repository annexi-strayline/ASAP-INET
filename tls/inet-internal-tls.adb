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

with Ada.Calendar;
with Interfaces.C.Strings;

with INET.TLS;
with INET.Internal.OS_Constants; use INET.Internal.OS_Constants;

pragma External_With ("inet-internal-tls-sys.c");

use Interfaces.C;

package body INET.Internal.TLS is
   
   TLS_Error           : exception renames INET.TLS.TLS_Error;
   TLS_Handshake_Failed: exception renames INET.TLS.TLS_Handshake_Failed;
   
   ---------------------
   -- Raise_TLS_Error --
   ---------------------
   
   function Context_Error_Message (Context: TLS_Context'Class) return String is
      use Interfaces.C.Strings;
      
      function tls_error (Context: in Context_Handle) return chars_ptr with
        Import => True, Convention => C, External_Name => "tls_error";
      
      -- <tls.h> tls_error(3). The returned string probably points to a buffer
      -- in Context somewhere. In any case, it does not need to be freed by
      -- the callee.
      
      error_string: constant chars_ptr := tls_error (Context.Handle);
   begin
      return (if error_string /= Null_Ptr then
                 Value (error_string)
              else
                 "[No error message available from libtls]");
   end Context_Error_Message;
   
   procedure Raise_TLS_Error (Context : in TLS_Context'Class; 
                              Preamble: in String) 
   with No_Return is
   begin
      raise TLS_Error with Preamble & ": " 
        & Context_Error_Message (Context);
   end Raise_TLS_Error;
   
   --
   -- libtls Imports
   --
   
   function tls_init return int with
     Import => True, Convention => C, External_Name => "tls_init";
   
   function tls_client return Context_Handle with
     Import => True, Convention => C, External_Name => "tls_client";
   
   function tls_server return Context_Handle with
     Import => True, Convention => C, External_Name => "tls_server";
   
   -- <tls.h> tls_client(3)
   
   function tls_configure (ctx   : Context_Handle;
                           config: INET_Extension_Handle)
                          return int
   with Import => True, Convention => C, External_Name => "tls_configure";
   
   function tls_close (ctx: in Context_Handle) return int with 
     Import => True, Convention => C, External_Name => "tls_close";
   
   procedure tls_reset (ctx: in Context_Handle) with
     Import => True, Convention => C, External_Name => "tls_reset";
   
   procedure tls_free (ctx: in Context_Handle) with
     Import => True, Convention => C, External_Name => "tls_free";
   
   -- <tls.h> tls_read(3)
   
   TLS_WANT_POLLIN: constant ssize_t with
       Import => True, Convention => C, 
       External_Name => "__inet_internal_tls_sys_TLS_WANT_POLLIN";
   
   TLS_WANT_POLLOUT: constant ssize_t with
       Import => True, Convention => C, 
       External_Name => "__inet_internal_tls_sys_TLS_WANT_POLLOUT";
   
   -- <tls.h> tls_read(3)
   
   --
   -- Common Facilities
   --
   
   -----------------------------
   -- Cryptographic_Randomize --
   -----------------------------
   
   -- The actual facilities to do this is very platform-dependent. So the
   -- actual platform-dependent part will be in the C part.
   
   -- (Arbitrary Data) --------------------------------------------------
   
   procedure Cryptographic_Randomize (Data : out Random_Data) is
      procedure cryptorand_buffer (buf:    out Random_Data;
                                   len: in     Interfaces.C.size_t)
      with Import => True, Convention => C,
        External_Name => "__inet_internal_tls_sys_cryptorand_buffer";
   begin
      if Data'Length = 0 then return; end if;
      cryptorand_buffer (buf => Data, len => Data'Length);
   end Cryptographic_Randomize;
   
   -- (Unsigned 32) -----------------------------------------------------
   
   procedure Cryptographic_Randomize (Value: out Interfaces.Unsigned_32) is
      function cryptorand_uint32 return Interfaces.Unsigned_32 with
        Import => True, Convention => C,
        External_Name => "__inet_internal_tls_sys_cryptorand_uint32";
   begin
      Value := cryptorand_uint32;
   end Cryptographic_Randomize;
   
   --
   -- TLS_Context
   --
   
   ---------------
   -- Available --
   ---------------
   
   function Available (Context: TLS_Context) return Boolean is
     (Context.Avail and then Context.Handle /= Null_Context_Handle);
   
   --------------
   -- Shutdown --
   --------------
   
   procedure Shutdown (Context: in out TLS_Context) is
      Retval: int;
   begin
      if not Context.Available then
         return;
      end if;
      
      Retval := tls_close (Context.Handle);
      Context.Avail := False;
      -- We might be tempted to say that the return value of close doesn't
      -- matter, because what can we do about it? But this is TLS, and
      -- security is important. We're explicit about every failure.
      
      if Retval /= 0 then
         Raise_TLS_Error (Context, "Failed to close TLS context");
      end if;
   end Shutdown;
   
   ---------------
   -- Handshake --
   ---------------
   
   procedure Handshake (Context: in out TLS_Context;
                        Socket : in     UNIX_Sockets.UNIX_Socket;
                        Timeout: in     Duration)
   is
      use Ada.Calendar;
      
      function tls_handshake (ctx: Context_Handle) return int with
        Import => True, Convention => C,
        External_Name => "tls_handshake";
      
      Mark : constant Time := Clock;
      Check: Time;
      
      Retval : ssize_t;
      Discard: int;
   begin
      if not Context.Avail then
         raise Program_Error with "Attempt to execute a TLS handshake on an "
           &                      "inactive context";
      end if;
      
      loop
         Retval := ssize_t (tls_handshake (Context.Handle));
         
         if Retval in TLS_WANT_POLLIN | TLS_WANT_POLLOUT then
            Check := Clock;
            if Check >= Mark + Timeout then
               Discard := tls_close (Context.Handle);
               raise TLS_Handshake_Failed with "Handshake timed-out";
            end if;
            
            UNIX_Sockets.Wait 
              (Socket => Socket,
               Direction => (if Retval = TLS_WANT_POLLIN then
                                UNIX_Sockets.Inbound
                             else
                                UNIX_Sockets.Outbound),
               
               Timeout   => (Mark + Timeout) - Check);
            
         elsif Retval < 0 then
            declare
               Error: constant String := Context_Error_Message (Context);
            begin
               Discard := tls_close (Context.Handle);
               raise TLS_Handshake_Failed with Error;
            end;
         else
            -- All good
            return;
         end if;
      end loop;
   end Handshake;
   
   --------------
   -- Finalize --
   --------------
   
   procedure Finalize (Context: in out TLS_Context) is
      Discard: int;
   begin
      if Context.Handle = Null_Context_Handle then return; end if;
      
      Discard := tls_close (Context.Handle);
      tls_free (Context.Handle);
   end Finalize;
   
   --
   -- TLS_Listener_Context
   -- 
   
   ---------------
   -- Configure --
   ---------------
   
   procedure Configure
     (Context      : in out TLS_Listener_Context;
      Configuration: in     INET.TLS.TLS_Server_Configuration'Class)
   is
      Retval : int;
      Discard: int;
      Config_Handle: INET_Extension_Handle;
   begin
      if Context.Available then
         Discard := tls_close (Context.Handle);
         tls_reset (Context.Handle);
         
      elsif Context.Handle = Null_Context_Handle then
         Context.Handle := tls_server;
         if Context.Handle = Null_Context_Handle then
            raise TLS_Error with "Unable to allocate new TLS server context" ;
         end if;
      end if;
      
      Context.Avail := False;
      Configuration.Get_External_Handle (Config_Handle);
      Retval := tls_configure (ctx    => Context.Handle,
                               config => Config_Handle);
      
      if Retval /= 0 then
         Raise_TLS_Error (Context, "Unable to configure TLS server context");
      else
         Context.Avail := True;
      end if;
      
   end Configure;
   
   --
   -- TLS_Stream_Context
   --
   
   ---------------
   -- Establish --
   ---------------
   
   procedure Establish
     (Context         : in out TLS_Stream_Context;
      Listener_Context: in     TLS_Listener_Context'Class;
      Socket          : in     UNIX_Sockets.UNIX_Socket;
      Timeout         : in     Duration)
   is
      function tls_accept_socket (ctx   : in     Context_Handle;
                                  cctx  :    out Context_Handle;
                                  socket: in     int)
                                 return int
      with Import => True, Convention => C,
        External_Name => "tls_accept_socket";
      
      s: constant int := UNIX_Sockets.TCP_Socket_Descriptor (Socket);
      Retval, Discard: int;
   begin
      if Context.Available then
         raise Program_Error with "Attempt to establish a TLS context "
           &                      "on an active context.";
         
      elsif not Listener_Context.Available then
         raise Program_Error with "Attempt to establish a TLS context "
           &                      "on an inactive listener context.";
      end if;
      
      -- No explicit check for the status of Socket because, tbh, that is
      -- not something the user can mess up, so it would be a bug in the
      -- INET subsystem, and would show up immediately.
      
      -- In the case of an Establish on an Listener_Context, unfortunately we
      -- cannot reuse an old context, since tls_accept_socket makes a new
      -- context so we need to deallocate it now,
      -- unconditionally. If the handle is null, this has no effect
      -- (tls_free(3))
      
      tls_free (Context.Handle);
      Context.Handle := Null_Context_Handle;
      
      -- tls_accept_socket(3) takes an established socket, not a listen
      -- socket, so this is a socket that's been accepted already at the
      -- TCP level
      
      Retval := tls_accept_socket (ctx    => Listener_Context.Handle,
                                   cctx   => Context.Handle,
                                   socket => s);
      
      if Retval /= 0 then
         tls_free (Context.Handle);
         Context.Handle := Null_Context_Handle;
         Raise_TLS_Error (Context, "Failed to establish TLS context");
      end if;
      
      Context.Avail := True;
      Context.Handshake (Socket, Timeout);
       
   exception
      when others =>
         Discard := tls_close (Context.Handle);
         Context.Avail := False;
         raise;
   end Establish;
   
   ----------------------------------------------------------------------
   
   procedure Establish
     (Context      : in out TLS_Stream_Context;
      Configuration: in     INET.TLS.TLS_Client_Configuration'Class;
      Socket       : in     UNIX_Sockets.UNIX_Socket;
      Timeout      : in     Duration)
   is begin
      Context.Establish (Configuration => Configuration,
                         Server_Name   => "",
                         Socket        => Socket,
                         Timeout       => Timeout);
   end Establish;
   
   ----------------------------------------------------------------------
   
   procedure Establish
     (Context      : in out TLS_Stream_Context;
      Configuration: in     INET.TLS.TLS_Client_Configuration'Class;
      Server_Name  : in     String;
      Socket       : in     UNIX_Sockets.UNIX_Socket;
      Timeout      : in     Duration)
   is
      use Interfaces.C.Strings;
      
      function tls_connect_socket (ctx       : Context_Handle;
                                   s         : int;
                                   servername: chars_ptr)
                                  return int
      with Import => True, Convention => C,
        External_Name => "tls_connect_socket";
      
      s: constant int := UNIX_Sockets.TCP_Socket_Descriptor (Socket);
      servername: aliased char_array := To_C (Server_Name);
      servername_ptr: constant chars_ptr 
        := (if Server_Name'Length > 0 then
               To_Chars_Ptr (servername'Unchecked_Access)
               -- We promoise that tls_connect_socket will not pass
               -- servername_ptr around all over the place after the call
            else
               Null_Ptr);
      
      Config_Handle: INET_Extension_Handle;
      
      Retval, Discard: int;
   begin
      if Context.Available then
         raise Program_Error with "Attempt to establish a TLS context "
           &                      "on an active context.";
      end if;
      
      Context.Avail := False; -- Should be redundant, but is safer
      
      -- For outbound establishments, we have the opportunity to re-use the
      -- context.
      
      if Context.Handle /= Null_Context_Handle then
         tls_reset (Context.Handle);
      else
         Context.Handle := tls_client;
         if Context.Handle = Null_Context_Handle then
            raise TLS_Error with "Failed to allocate TLS context";
         end if;
      end if;
      
      -- Now we configure the session
      Configuration.Get_External_Handle (Config_Handle);
      Retval := tls_configure (ctx    => Context.Handle,
                               config => Config_Handle);
      
      if Retval /= 0 then
         Raise_TLS_Error (Context, "TLS context configuration failed");
         -- We don't need to do anything else here since Context.Available
         -- will be false due to Context.Avail being false;
      end if;
      
      Retval := tls_connect_socket 
        (ctx        => Context.Handle,
         s          => s,
         servername => servername_ptr);
      
      if Retval /= 0 then
         Raise_TLS_Error (Context, "TLS socket-context association failed");
      end if;
      
      Context.Avail := True;
      Context.Handshake (Socket, Timeout);
       
   exception
      when others =>
         Discard := tls_close (Context.Handle);
         Context.Avail := False;
         raise;
      
   end Establish;

   ------------------------
   -- TLS_Send_Immediate --
   ------------------------
   
   procedure TLS_Send_Immediate 
     (Context: in out TLS_Stream_Context;
      Buffer : in     Ada.Streams.Stream_Element_Array;
      Last   :    out Ada.Streams.Stream_Element_Offset)
   is
      use Ada.Streams;
      
      function tls_write (ctx: Context_Handle;
                          buf: Stream_Element_Array;
                          buflen: size_t)
                         return ssize_t
      with Import => True, Convention => C, External_Name => "tls_write";
      
      Retval: ssize_t;
   begin
      if not Context.Available then 
         raise Program_Error with 
           "Attempted TLS write via an inactive context";
      elsif Buffer'Length < 1 then
         Last := Buffer'First - 1;
         return;
      end if;
      
      Retval := tls_write (ctx     => Context.Handle,
                           buf     => Buffer,
                           buflen => Buffer'Length);
      
      if Retval > 0 then
         Last := Buffer'First + Stream_Element_Offset (Retval) - 1;
         
      elsif Retval = TLS_WANT_POLLOUT then
         -- Outbound buffer is full
         Last := Buffer'First - 1;
         
      else
         Raise_TLS_Error (Context, "TLS write failed");
      end if;
   end;
   
   ---------------------------
   -- TLS_Receive_Immediate --
   ---------------------------
   
   procedure TLS_Receive_Immediate
     (Context: in out TLS_Stream_Context;
      Buffer :    out Ada.Streams.Stream_Element_Array;
      Last   :    out Ada.Streams.Stream_Element_Offset)
   is
      use Ada.Streams;
      
      function tls_read (ctx   : Context_Handle;
                         buf   : Stream_Element_Array;
                         buflen: size_t)
                        return ssize_t
      with Import => True, Convention => C, External_Name => "tls_read";
      
      Retval: ssize_t;
   begin
      if not Context.Available then
         raise Program_Error with 
           "Attempted TLS write via an inactive context";
      elsif Buffer'Length < 1 then
         Last := Buffer'First - 1;
         return;         
      end if;
      
      Retval := tls_read (ctx     => Context.Handle,
                          buf     => Buffer,
                          buflen => Buffer'Length);
      
      if Retval > 0 then
         Last := Buffer'First + Stream_Element_Offset (Retval) - 1;
         
      elsif Retval = TLS_WANT_POLLIN then
         -- Nothing available in the (decrypted) buffer
         Last := Buffer'First - 1;
         
      else
         Raise_TLS_Error (Context, "TLS read failed");
      end if;
   end TLS_Receive_Immediate;
   
begin
   -- Initialize libtls
   if tls_init /= 0 then
      raise Program_Error with "Failed to initialize libtls";
   end if;
   
end INET.Internal.TLS;
