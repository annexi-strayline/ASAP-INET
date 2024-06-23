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


with Ada.Streams; use Ada.Streams;

with INET.IP;

private with Interfaces.C;
private with INET.Internal.UNIX_Sockets;


package INET.TCP is  
   
   TCP_Timeout            : exception;
   TCP_Lookup_Failed      : exception;
   TCP_Buffer_Full        : exception;
   TCP_Connection_Reset   : exception;
   TCP_Connection_Refused : exception;
   TCP_Host_Unreachable   : exception;
   TCP_Net_Unreachable    : exception;
   TCP_System_Error       : exception;
   TCP_Bind_Unauthorized  : exception;
   TCP_Bind_Occupied      : exception;
   TCP_Listener_Not_Bound : exception;
   
   type TCP_Port is range 0 .. 2**16 - 1;
   -- IETF RFC 793/STD 7, Section 3.1
   
   --------------------
   -- TCP_Connection --
   --------------------
   
   type TCP_Connection is limited new Root_Stream_Type with private;
   
   -- TCP_Connection objects are NOT task-safe.
   
   -- Stream Properties --
   -----------------------
   
   overriding 
   procedure Read (Stream: in out TCP_Connection;
                   Item  :    out Stream_Element_Array;
                   Last  :    out Stream_Element_Offset);
   -- Read attempts to read the entire Item buffer from the connection. If
   -- an error occurs, an exception is propegated any any partially read data
   -- is lost. If the remote peer closes the connectio normally (shutdown),
   -- this is not considered an "error", and Read will simply return with Last
   -- < Item'Last. When using the stream interface, this would trigger an
   -- End_Error exception from the RTL.
   
   procedure Read_Immediate (Stream: in out TCP_Connection;
                             Item  :    out Stream_Element_Array;
                             Last  :    out Stream_Element_Offset);
   -- Attempts to receive as much of Item as is currently available in the
   -- operating system's buffer.
   --
   -- Read_Immediate does not block, and does not raise any TCP_ series 
   -- exceptions.
   
   overriding
   procedure Write (Stream: in out TCP_Connection;
                    Item  : in     Stream_Element_Array);
   -- If a timeout occurs due to Set_Read_Timeout being set, Write will raise
   -- TCP_Timeout. It is possible that some of Item will have been transmitted.
   
   procedure Write_Immediate (Stream: in out TCP_Connection;
                              Item  : in     Stream_Element_Array;
                              Last  :    out Stream_Element_Offset);
   -- Attempts to write as much of Item as can be placed in the operating
   -- system's buffer.
   --
   -- Write_Immediate does not block, and does not raise TCP_ series exceptions.
   
   
   -- Connection Properties --
   ---------------------------
   
   function  Destination_Address (Connection: TCP_Connection) 
                                 return IP.IP_Address;
   
   function  Destination_Port    (Connection: TCP_Connection) 
                                 return TCP_Port;
   
   -- For accepted connections, these will be for the client
   
   
   -- Timeout Properties --
   ------------------------
   
   procedure Read_Timeout   (Connection: in out TCP_Connection; 
                             Timeout   : in     Duration);
   
   procedure Read_Never_Timeout (Connection: in out TCP_Connection);
   
   procedure Write_Timeout  (Connection: in out TCP_Connection;
                             Timeout   : in     Duration);
   
   procedure Write_Never_Timeout (Connection: in out TCP_Connection);
   
   -- This setting is specific to the TCP_Connection object, and persists
   -- across connections.
   --
   -- If Read/Write_Timeout are set to 0.0, calls to Read/Write will be
   -- equivalent to Read/Write_Immediate. For Ada stream 'Read invocations,
   -- this means that insufficient data will result in an End_Error exception,
   -- and the data will be lost. In the case of 'Write invocations, a
   -- TCP_Buffer_Full exception is explicitly raised if the write was not
   -- completed.
   --
   -- The internal implementation of TCP_Connection timeouts is designed to be
   -- resistent to "Slowloris" attacks, particularily when reading Strings or
   -- to simple buffers directly. The timeout is absolute for each call to Read
   -- resp Write. The timer is NOT reset upon receipt of data, but instead sets
   -- a bound to the total duration of a Read resp Write operation.
   
   -- Connection_Management --
   ---------------------------
   
   procedure Connect (Connection: in out TCP_Connection;
                      Address   : in     IP.IP_Address;
                      Port      : in     TCP_Port);
   
   procedure Connect (Connection: in out TCP_Connection;
                      Host_Name : in     String;
                      Port      : in     TCP_Port)
   with Pre'Class => Host_Name'Length > 0;
   
   procedure Connect (Connection   : in out TCP_Connection;
                      Host_Name    : in     String;
                      Port         : in     TCP_Port;
                      Version      : in     IP.IP_Version)
   with Pre'Class => Host_Name'Length > 0;
   
   -- Attempts to connect a TCP_Connection object to the specified endpoint.
   --
   -- If Connection is already connected, Shutdown is invoked, and the
   -- existing connection is destroyed. This happens regardless of the outcome
   -- of the subsequent connection attempt.
   --
   -- When obtaining the address vi a Host_Name, if Version is specified,
   -- only address of that IP version will be used to complete the connection.
   -- Otherwise, the first address returned by the lookup is used.
   --
   -- If the connection fails, the appropriate TCP_ exception is raised.
   
   procedure Shutdown       (Connection: in out TCP_Connection);
   procedure Shutdown_Read  (Connection: in out TCP_Connection);
   procedure Shutdown_Write (Connection: in out TCP_Connection);
   
   -- See man page shutdown(2)
   
   ------------------
   -- TCP_Listener --
   ------------------
   
   type TCP_Listener (Queue_Size: Positive) is tagged limited private;
   
   -- TCP_Listener objects ARE task-safe
   --
   -- Queue_Size is the number of connections that can be pending Dequeue
   -- on the listener. This is often known as the "backlog".
   
   function  Is_Bound (Listener: TCP_Listener) return Boolean;
   -- Returns True iff the Listener is currently bound to an address
   -- or socket
   
   procedure Bind (Listener: in out TCP_Listener;
                   Address : in     IP.IP_Address;
                   Port    : in     TCP_Port)
   with Pre'Class => not Listener.Is_Bound;
   -- Attempts to bind a listener to the provided Address and Port.
   --
   -- The Bind Address determins the IP version of the listener, and thus
   -- can only be executed once. A listener cannot be unbound.
   --
   -- -- All Possible Exceptions --
   -- *  Program_Error        : Listener is already bound.
   -- *  TCP_Bind_Unauthorized: The operating system did not permit binding to
   --                           the specified address/port
   -- *  TCP_Bind_Occupied    : A different listener is already bound to the
   --                           specified address/port
   -- *  TCP_System_Error     : An unexpected error occured

   procedure Dequeue (Listener  : in out TCP_Listener;
                      Connection: in out TCP_Connection'Class)
   with Pre'Class => Listener.Is_Bound;
   
   function Dequeue (Listener: in out TCP_Listener) return TCP_Connection'Class
   with Pre'Class => Listener.Is_Bound;
   
   -- Waits for a connection to become available on Listener.
   --
   -- If the Precondition is not held, TCP_Listener_Not_Bound is raised,
   -- otherwise, unexpected errors result in 1TCP_System_Error.
   --
   -- If Connection is already connected, Shutdown is invoked and the
   -- connection is destroyed immediately on entry into Dequeue, before
   -- waiting.
   --
   -- It might not be wise to have multiple tasks waiting on the Dequeue of a
   -- single TCP_Listener. Due to the underlying system call, this should work
   -- fine, but the behaviour might not be reliable. It is probably better to
   -- dequeue from one task and then dispatch the connections to a queue of
   -- form.

   
private
   
   package UNIX_Sockets renames Internal.UNIX_Sockets;
   
   use type UNIX_Sockets.Transport_Protocol;
   
   type TCP_Connection is limited new Root_Stream_Type with
      record
         Socket             : UNIX_Sockets.UNIX_Socket (UNIX_Sockets.TCP);
         
         Destination_Address: IP.IP_Address;
         Destination_Port   : TCP_Port;
         
         Read_Does_Timeout : Boolean := False;
         Write_Does_Timeout: Boolean := False;
         -- True means there is a timeout
         
         Read_Timeout : Duration := 0.0; 
         Write_Timeout: Duration := 0.0;
         -- A value of 0.0 when Read/Write_Does_Timeout is False means
         -- that Read/Write are analogous to calls to Read/Write_Immediate
         
      end record;
   
   -- Some generic, TCP_Connection-specific implementations of Read/Write.
   -- These are provided so that child extension packages, such as TLS, can
   -- override Read/Write to use alternate calls for the actual read/write
   -- operation, while re-using the code for polling and checking for timeout
   
   generic
      type Connection_Type is limited new TCP_Connection with private;

      with procedure Connection_Receive_Immediate
        (Connection: in out Connection_Type;
         Buffer    :    out Stream_Element_Array;
         Last      :    out Stream_Element_Offset;
         Status    :    out UNIX_Sockets.Operation_Status;
         Errno     :    out Interfaces.C.int);
   procedure Generic_Read (Stream: in out Connection_Type;
                           Item  :    out Stream_Element_Array;
                           Last  :    out Stream_Element_Offset);
   
   generic
      type Connection_Type is limited new TCP_Connection with private;
      
      with procedure Connection_Send_Immediate
        (Connection: in out Connection_Type;
         Buffer    : in     Stream_Element_Array;
         Last      :    out Stream_Element_Offset;
         Status    :    out UNIX_Sockets.Operation_Status;
         Errno     :    out Interfaces.C.int);
   procedure Generic_Write (Stream: in out Connection_Type;
                            Item  : in     Stream_Element_Array);

   protected type Listener_Bound_Flag is
      procedure Set_Bound;
      function  Is_Bound return Boolean;
   private
      Bound_Flag: Boolean := False;
   end Listener_Bound_Flag;
   
   
   type TCP_Listener (Queue_Size: Positive) is tagged limited 
      record
         Bound_Flag: Listener_Bound_Flag;
         Socket    : UNIX_Sockets.UNIX_Socket (UNIX_Sockets.TCP);
      end record;
   
end INET.TCP;
