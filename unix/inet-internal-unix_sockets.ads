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

with Ada.Streams; use Ada.Streams;

        with INET.IP;
limited with INET.TCP;

with Interfaces.C;
with Ada.Finalization;

package INET.Internal.UNIX_Sockets is
   
   type Operation_Status is
     (OK,
      Not_Ready,
      Timedout,
      Not_Connected,
      Connection_Reset,
      Connection_Refused,
      Net_Unreachable,
      Host_Unreachable,
      Unauthorized,
      Address_Occupied,
      Other_Failure);
   
   type Transport_Protocol is (TCP, UDP);
   
   type UNIX_Socket (Protocol: Transport_Protocol) is limited private;
   
   function Socket_Active (Socket: UNIX_Socket) return Boolean;
   
   -- Returns True if the socket has been allocated and is active.
   --
   -- For UDP sockets, this always returns True.
   
   procedure TCP_Connect (Socket : in out UNIX_Socket;
                          Address: in     IP.IP_Address;
                          Port   : in     INET.TCP.TCP_Port;
                          Status :    out Operation_Status;
                          Errno  :    out Interfaces.C.int)
   with Pre => Socket.Protocol = TCP;
   
   -- Attempts to connect the Socket to the specified Address and Port. The
   -- Socket shall be a new socket and shall not be already connected or
   -- listening.
   --
   -- If the socket is already allocated, it is closed and a new one is
   -- allocated. This behaviour is required in order for Address to be either
   -- v4 or v6, and follows the capabilities of the higher-level TCP_Connection
   -- type.
   --
   -- Errno can be queried in the case of Other_Failure to build a more
   -- informative exception message.
   
   procedure TCP_Bind_Listener (Socket : in out UNIX_Socket;
                                Address: in     IP.IP_Address;
                                Port   : in     INET.TCP.TCP_Port;
                                Backlog: in     Positive;
                                Status :    out Operation_Status;
                                Errno  :    out Interfaces.C.int)
   with Pre => Socket.Protocol = TCP;
   
   -- Attempts to both bind and initiate listening on Socket. The Socket shall
   -- be a new socket and shall not already by connected or listening.
   --
   -- If the socket is already allocated, Program_Error is raised.
   --
   -- Errno can be queries in the case of Other_Failure to build a more
   -- informative exception message. Errno may be set by either the bind or
   -- listen process.
   
   procedure TCP_Accept_Connection (Listen_Socket : in     UNIX_Socket;
                                    New_Socket    : in out UNIX_Socket;
                                    Client_Address:    out IP.IP_Address;
                                    Client_Port   :    out INET.TCP.TCP_Port;
                                    Status        :    out Operation_Status;
                                    Errno         :    out Interfaces.C.int)
   with Pre => Listen_Socket.Protocol = TCP and Socket_Active (Listen_Socket)
               and New_Socket.Protocol = TCP;
   
   -- Blocks indefinately for a connection to arrive on Listen_Socket. This
   -- Connection is then set on New_Socket. Client_Address and Client_Port
   -- are updated to indicate the address and port of the client at the other
   -- end of New_Socket.
   --
   -- Status will typically be either OK, or Other_Failure, since failures
   -- are not normally expected on accept operations
   --
   -- If New_Socket is already active, it is closed immediately on entry to
   -- TCP_Accept_Connection.
                                   
   
   type Data_Direction is (Outbound, Inbound, Both);
   
   procedure TCP_Shutdown (Socket   : in out UNIX_Socket;
                           Direction: in     Data_Direction)
   with Pre => Socket.Protocol = TCP;
   
   -- Invokes the TCP "Shutdown" procedure for the socket in the given
   -- direction. If the socket is already shutdown, no action is taken.
   
   
   procedure TCP_Receive_Immediate (Socket   : in out UNIX_Socket;
                                    Buffer   :    out Stream_Element_Array;
                                    Last     :    out Stream_Element_Offset;
                                    Status   :    out Operation_Status;
                                    Errno    :    out Interfaces.C.int)
   with Pre => Socket.Protocol = TCP and Socket_Active (Socket);
   
   -- Receives as much data as is immediately available into Buffer, and
   -- indicates the amount of data received with Last.
   --
   -- All UNIX_Socket objects are non-blocking. 
   --
   -- If Peek is True, the data is left on the operating system's buffer, and
   -- will be re-read on the next Receive
   --
   -- errno is set only if Status is not OK
   
   procedure TCP_Send_Immediate (Socket   : in out UNIX_Socket;
                                 Buffer   : in     Stream_Element_Array;
                                 Last     :    out Stream_Element_Offset;
                                 Status   :    out Operation_Status;
                                 Errno    :    out Interfaces.C.int)
   with Pre => Socket.Protocol = TCP and Socket_Active (Socket);
   
   -- Sends as much data as is immediately possible from Buffer, and indicates
   -- the amount of data actually sent with Last. 
   --
   -- Status should be checked if Last < Buffer'Last. A status of "OK"
   -- indicates the OS has no more space in the outbound buffer.
   --
   -- errno is set only if Status is not OK
   
   procedure Wait (Socket   : in UNIX_Socket;
                   Direction: in Data_Direction);
   
   procedure Wait (Socket   : in UNIX_Socket;
                   Direction: in Data_Direction;
                   Timeout  : in Duration)
   with Pre => Timeout > 0.0;
   
   -- Waits for the socket to be ready for operations in the selected
   -- direction. A call to Wait may be interrupted by a signal or error, and
   -- should always be followed by TCP_Receive_Immediate or TCP_Send_Immediate.
   -- This operation is intended to allow a task to sleep on a socket.
   
   function TCP_Socket_Descriptor (Socket: UNIX_Socket) 
                                  return Interfaces.C.int 
   with Pre => Socket_Active (Socket) and Socket.Protocol = TCP;
   
   procedure UDP_Socket_Descriptors 
     (Socket         : in     UNIX_Socket;
      IPv4_Descriptor:    out Interfaces.C.int;
      IPv6_Descriptor:    out Interfaces.C.int)
   with Pre => Socket_Active (Socket) and Socket.Protocol = UDP;
   
   -- Returns the underlying descriptor number for a Socket. This facility is
   -- available for layered protocols such as TLS which need to drive the
   -- socket IO directly.
   --
   -- These descriptors shall be used immediately and not stored elsewhere.
   
   
private
   
   use Interfaces.C;

   Invalid_Descriptor: constant := -1;
   
   type UNIX_Socket (Protocol: Transport_Protocol) is limited
     new Ada.Finalization.Limited_Controlled with
      record
         case Protocol is
            when TCP =>
               TCP_Socket   : int := Invalid_Descriptor;
               
            when UDP =>
               UDP_v4_Socket: int := Invalid_Descriptor;
               UDP_v6_Socket: int := Invalid_Descriptor;
         end case;
         
      end record;
   
   overriding procedure Initialize (Socket: in out UNIX_Socket);
   overriding procedure Finalize   (Socket: in out UNIX_Socket);
   
end INET.Internal.UNIX_Sockets;
