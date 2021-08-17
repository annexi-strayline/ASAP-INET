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

-- This package provides low-level interfaces to libtls for the management of
-- "contexts", and the sending and receiving of data through those contexts

with Ada.Streams;
with Ada.Finalization;
with Interfaces.C;

limited with INET.TLS;
with INET.Internal.UNIX_Sockets;

package INET.Internal.TLS is
   
   package UNIX_Sockets renames Internal.UNIX_Sockets;
   
   -----------------------
   -- Common Facilities --
   -----------------------
   
   use type Interfaces.C.size_t;
   
   type Random_Data is 
     array (Interfaces.C.size_t range <>) of Interfaces.C.unsigned_char with
     Pack => True, Convention => C;
   
   procedure Cryptographic_Randomize (Data : out Random_Data);
   procedure Cryptographic_Randomize (Value: out Interfaces.Unsigned_32);
   
   -- Provides cryptographically random values for arbitrary data
   -- (usually keys), or unsigned 32-bit integers. This means high-entropy
   -- random data, typically harvested by the operating system.
   
   -----------------
   -- TLS_Context --
   -----------------
   
   type TLS_Context is abstract tagged limited private;
   
   -- A TLS_Context represents the state of a TLS connection, and libtls
   -- needs the context in order to send or receive. The context is configured
   -- for each connection, and eventually associated with a socket.
   
   function  Available (Context: TLS_Context) return Boolean;
   
   -- True if the context has been configured OR established
   
   procedure Shutdown (Context: in out TLS_Context) with
     Post'Class => not Context.Available;
   
   -- Closes-down the underlying session, but does not reset or free the
   -- context. Those operations are handled by finalization or one of
   -- the Establish or Configure operations of the derrived types
   
   procedure Handshake (Context: in out TLS_Context;
                        Socket : in     UNIX_Sockets.UNIX_Socket;
                        Timeout: in     Duration)
   with
     Pre'Class => Context.Available;
   
   -- Causes a TLS handshake to be executed immediately. If the handshake
   -- fails, TLS_Handshake_Failed is propegated with the corresponding error
   -- message from libtls
   --
   -- If the handshake times-out, TLS_Handshake_Failed will be raised, but
   -- the context will not be closed.
   --
   -- If Context is not Available, Program_Error is raised

   --------------------------
   -- TLS_Listener_Context --
   --------------------------
   
   type TLS_Listener_Context is limited new TLS_Context with private;
   
   not overriding
   procedure Configure 
     (Context      : in out TLS_Listener_Context;
      Configuration: in     INET.TLS.TLS_Server_Configuration'Class)
   with Post'Class => Context.Available;
   
   -- TLS_Listener_Contexts are configured with a handle from a 
   -- TLS_Server_Configuration'Class object, and is able to initialize new
   -- TLS_Stream_Contexts
   --
   -- The Caller shall ensure that Configuration is from a
   -- TLS_Server_Configuration object
   --
   -- If the context is already Available, the context is closed and reset.
   --
   -- ** Note **
   -- libtls internally links the configuration to the context, and so as long
   -- as the TLS_Configuration object remains visible, it can be modified
   -- directly, such as adding ticket keys, and this will affect all associated
   -- contexts. A full reconfiguration is therefore not necessary for such
   -- operations.
   
   ------------------------
   -- TLS_Stream_Context --
   ------------------------
   
   type TLS_Stream_Context is limited new TLS_Context with private;
   -- "native" TLS: A context for reliable stream transports (usually TCP or
   -- SCTP).
   
   not overriding
   procedure Establish
     (Context         : in out TLS_Stream_Context;
      Listener_Context: in     TLS_Listener_Context'Class;
      Socket          : in     UNIX_Sockets.UNIX_Socket;
      Timeout         : in     Duration)
   with 
     Pre'Class  =>     not Context.Available
                   and Listener_Context.Available
                   and UNIX_Sockets.Socket_Active (Socket),
     Post'Class => Context.Available;
   
   -- Setting up a new server TLS stream via a TLS_Listener_Context.
   
   not overriding
   procedure Establish
     (Context      : in out TLS_Stream_Context;
      Configuration: in     INET.TLS.TLS_Client_Configuration'Class;
      Socket       : in     UNIX_Sockets.UNIX_Socket;
      Timeout      : in     Duration)
   with 
     Pre'Class  => not Context.Available and
                   UNIX_Sockets.Socket_Active (Socket),
     Post'Class => Context.Available;
   
   -- Setting up a new TLS stream to a remote server
   
   not overriding
   procedure Establish
     (Context      : in out TLS_Stream_Context;
      Configuration: in     INET.TLS.TLS_Client_Configuration'Class;
      Server_Name  : in     String;
      Socket       : in     UNIX_Sockets.UNIX_Socket;
      Timeout      : in     Duration)
   with 
     Pre'Class  => not Context.Available and
                   UNIX_Sockets.Socket_Active (Socket),
     Post'Class => Context.Available;
   
   -- Setting up a new TLS stream to a remote server with SNI
   
   -- Sets up and configures, TLS context, associating it with some existing
   -- TCP connection, and then invokes Hanshake on Context.
   --
   -- If Context is currently Available, Program_Error is raised.
   --
   -- If Server_Name is specified, the SNI extension (RFC 4366) is enforced.
   --
   -- Any failure raises TLS_Error with an appropriate message.
   --
   -- Timeout is passed directly to Handshake, with the same consequences
   
   not overriding
   procedure TLS_Send_Immediate 
     (Context: in out TLS_Stream_Context;
      Buffer : in     Ada.Streams.Stream_Element_Array;
      Last   :    out Ada.Streams.Stream_Element_Offset)
   with
     Pre'Class => Context.Available;
   
   not overriding
   procedure TLS_Receive_Immediate
     (Context: in out TLS_Stream_Context;
      Buffer :    out Ada.Streams.Stream_Element_Array;
      Last   :    out Ada.Streams.Stream_Element_Offset)
   with
     Pre'Class => Context.Available;
   
   -- Attempts to Send or Receive over an established TLS context. The
   -- underlying socket is assumed to be non-blocking.
   --
   -- If an error occurs, TLS_Error is raised with the appropriate error
   -- message.
   
--   type TLS_Datagram_Context is limited new TLS_Context with private;
   -- DTLS: A context for (unreliable) datagram transports.
   
   -- ** Future implementation ** --
   
private
   
   type Context_Handle is new INET_Extension_Handle;
   
   -- A "C" pointer to the "struct tls" structure in libtls. This is a
   -- transparent structure
   
   Null_Context_Handle: constant Context_Handle 
     := Context_Handle (Null_Handle);
   
   type TLS_Context is abstract limited 
     new Ada.Finalization.Limited_Controlled with
      record
         Avail : Boolean        := False;
         Handle: Context_Handle := Null_Context_Handle;
      end record;
   
   overriding
   procedure Finalize (Context: in out TLS_Context);
   
   -- Deactivates and deinitializes Context
   
   type TLS_Listener_Context is limited new TLS_Context with null record;
   type TLS_Stream_Context   is limited new TLS_Context with null record;

   
end INET.Internal.TLS;
