------------------------------------------------------------------------------
--                                                                          --
--                    Internet Protocol Suite Package                       --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2020, Inc.                                                --
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

-- This package implements an extension of TCP_Connection that is secured with
-- TLS.

with INET.TLS; use INET.TLS;

private with INET.Internal.TLS;

package INET.TCP.TLS is
   
   Explicit_Handshake_Timeout: constant Duration := 30.0;
   
   -- TODO: Migrate to AURA config. This might end up in TLS_Configuration, but
   -- this seems problematic since libtls executes handshakes on it's own
   -- volition, and we can't control the timeouts of those. It might be
   -- misleading to put that property there
   
   --------------------
   -- TLS_Connection --
   --------------------
   
   type TLS_Connection is abstract limited new TCP_Connection with private;
   
   -- TLS_Connection is an extension of TCP_Connection, and behaves in the
   -- same way, with the underlying communications being secured by TLS.
   --
   -- If Configuration is null, the connection can only be established
   -- via TLS_Listener.Dequeue (and thus is a server-side connection)
   --
   -- For security-concious applications where client authentication is
   -- also requred (and thus the Configuration contains private keys),
   -- Clear_Keys can be invoked on Configuration after the required
   -- TCP_Connections have been established. 
   
   not overriding
   function Secured (Connection: TLS_Connection) return Boolean;
   
   -- True iff the Connection has successfull established a TLS session
   -- over the underlying TCP connection.
   --
   -- Default initialized TLS_Connection'Class objects return False.
   --
   -- If a TLS_Connection is Dequeued from a TCP_Listener'Class object that
   -- is not a member of TLS_Listener'Class, Established will return False.
   --
   -- Read or Write operations are illegal if Secured is false and
   -- will cause Program_Error to be raised.
   --
   -- Unsecured connections can be secured by the Secure operation
   --
   -- See the description of Secure for example applications of
   -- unsecured TLS_Connection objects.
   
   overriding
   procedure Read (Stream: in out TLS_Connection;
                   Item  :    out Stream_Element_Array;
                   Last  :    out Stream_Element_Offset)
   with Pre => Stream.Secured;
   
   -- Semantics are preserved as with TCP_Connection.
   --
   -- Program_Error is raised if the connection has not yet been Secured.
   
   overriding
   procedure Read_Immediate (Stream: in out TLS_Connection;
                             Item  :    out Stream_Element_Array;
                             Last  :    out Stream_Element_Offset)
   with Pre => Stream.Secured;
   
   -- Semantics are preserved as with TCP_Connection
   --
   -- Program_Error is raised if the connection has not yet been Secured.
   
   overriding
   procedure Write (Stream: in out TLS_Connection;
                    Item  : in     Stream_Element_Array)
   with Pre => Stream.Secured;
   
   -- Semantics are preserved as with TCP_Connection
   --
   -- Program_Error is raised if the connection has not yet been Secured.
   
   overriding
   procedure Write_Immediate (Stream: in out TLS_Connection;
                              Item  : in     Stream_Element_Array;
                              Last  :    out Stream_Element_Offset)
   with Pre => Stream.Secured;
   
   -- Semantics are preserved as with TCP_Connection
   --
   -- Program_Error is raised if the connection has not yet been Secured.
   
   overriding procedure Shutdown       (Connection: in out TLS_Connection);
   overriding procedure Shutdown_Read  (Connection: in out TLS_Connection);
   overriding procedure Shutdown_Write (Connection: in out TLS_Connection);
   
   -- Shutdown Read and Shutdown Write are not supported for TLS connections
   -- at the socket (TCP) level. In order to preserve the behaviour as much as
   -- possible, the _Read and _Write variations will cause raise End_Error if
   -- a subsequent read/write is performed on the shutdown direction.
   --
   -- If both are invoked, Shutdown is invoked automatically.
   
   ---------------------------
   -- TLS_Client_Connection --
   ---------------------------
   
   type TLS_Client_Connection 
     (Configuration: not null access TLS_Client_Configuration'Class) 
     is limited new TLS_Connection with private;
   
   -- A TLS_Client_Connection is only able to form outbound connections.
   
   overriding
   procedure Connect (Connection: in out TLS_Client_Connection;
                      Address   : in     IP.IP_Address;
                      Port      : in     TCP_Port) 
   with No_Return;  -- Raises Program_Error
   
   not overriding
   procedure Connect (Connection : in out TLS_Client_Connection;
                      Address    : in     IP.IP_Address;
                      Port       : in     TCP_Port;
                      Server_Name: in     String)
   with Pre'Class => Server_Name'Length > 0;
   
   overriding
   procedure Connect (Connection: in out TLS_Client_Connection;
                      Host_Name : in     String;
                      Port      : in     TCP_Port);
   
   overriding
   procedure Connect (Connection   : in out TLS_Client_Connection;
                      Host_Name    : in     String;
                      Port         : in     TCP_Port;
                      Version      : in     IP.IP_Version);
   
   -- Attempts to establish a TLS connection over an new TCP connection.
   -- If Connection is already connected (or Secured), it is first shutdown.
   --
   -- TLS requires the verification of the server's hostname as part of the
   -- handshake, therefore connecting with only an Address and a Port requires
   -- a supplimental Server_Name. If the inherited Address-only Connect is
   -- invoked, Program_Error is raised.
   --
   -- It is generally recommended to use the inhereted Host_Name lookup
   -- operations for outbound TLS connections.
   
   not overriding
   procedure Secure (Connection : in out TLS_Client_Connection;
                     Server_Name: in     String)
   with Pre'Class  => Server_Name'Length > 0,
        Post'Class => Connection.Secured;
   
   -- Secure completes a TLS handshake initiated by the remote peer
   -- (the server). If it returns without error, TLS has been successfully
   -- established for the connection, according to Connection.Configuration.
   --
   -- If the connection is already Secured, Secure forces another handshake.
   -- This works even if Shutdown_Read or Shutdown_Write has been invoked
   -- (but not both, nor Shutdown - which makes the connection inactive).
   --
   -- If a Server_Name is specified, this will be used to verify the server
   -- name through the SNI extension (RFC4366). If Server_Name is a null string,
   -- Constraint_Error is raised.
   --
   -- If the connection has been fully Shutdown, Program_Error is raised.
   --
   -- If Secure fails, the connection is shutdown, and an exception is
   -- always propegated.
   --
   -- The remote peer must be a server, or else the TLS handshake will fail.
   -- Therefore, if Connection was initialized by a Dequeue from a TCP_Listener,
   -- TLS_Error is all but guaranteed.
   --
   -- For special application protocols that may start as plain-text,
   -- such as SMTP with STARTTLS, the socket may be first view converted
   -- upwards to a TCP_Connection, Connect invoked on that converion, and
   -- the subsequent plain-text negotiation. When ready to establish a TLS
   -- connection, Secure can be then be invoked on the underlying 
   -- TLS_Client_Connection object.
   
   ---------------------------
   -- TLS_Server_Connection --
   ---------------------------
   
   type TLS_Server_Connection is limited new TLS_Connection with private;
   
   -- TLS_Server_Connection objects do not need a configuration if Dequeued
   -- from a TLS_Listener. The context is implicitly configured from the
   -- TLS_Listener, which is configured via a TLS_Server_Configuration
   -- access discriminant
   
   overriding
   procedure Connect (Connection: in out TLS_Server_Connection;
                      Address   : in     IP.IP_Address;
                      Port      : in     TCP_Port)
   with No_Return;
   
   procedure Connect (Connection: in out TLS_Server_Connection;
                      Host_Name : in     String;
                      Port      : in     TCP_Port)
   with No_Return;
   
   procedure Connect (Connection   : in out TLS_Server_Connection;
                      Host_Name    : in     String;
                      Port         : in     TCP_Port;
                      Version      : in     IP.IP_Version)
   with No_Return;
   
   -- Connect is not legal on a server connection. Invoking Connect raises
   -- Program_Error.
   
   not overriding
   procedure Secure (Connection   : in out TLS_Server_Connection;
                     Configuration: in     TLS_Server_Configuration'Class)
   with Pre'Class  => not Connection.Secured,
        Post'Class => Connection.Secured;
   
   -- Secure initiates a TLS handshake with the remote peer (the client). 
   -- If it returns without error, TLS has been successfully established for
   -- the connection, according to the Configuration.
   --
   -- Due to the presence of the Configuration parameter, which is non-
   -- sensical on an established connection, invoking Secure on a Secured
   -- connection raises Program_Error.
   --
   -- To force a handshake, see Re_secure below.
   --
   -- If the connection has been fully Shutdown, Program_Error is raised.
   --
   -- If Secure fails, the connection is shutdown, and an exception is
   -- always propegated.
   --
   -- The remote peer must be a client, or else the TLS handshake will fail.
   -- Therefore, if Connection was initialized by a Connect via a upwards
   -- view conversion. TLS_Error is all but guaranteed.
   --
   -- For special application protocols that may start as plain-text,
   -- such as SMTP with STARTTLS, the socket may be dequeued from a
   -- regular TCP_Listener (rather than a TLS_Listener), and then
   -- view converted up to a regular TCP_Connection to perform the clear-text
   -- negotiation. When ready to establish a TLS connection, Secure can be
   -- then be invoked on the underlying TLS_Server_Connection object.
   
   not overriding
   procedure Re_Secure (Connection: in out TLS_Server_Connection) with
     Pre'Class => Connection.Secured;
   
   -- Connection must already be Secured, or else Program_Error is raised.
   -- Otherwise, Re_secure forces a handshake immediately. If Re_secure
   -- returns successfully, the handshake was successful.
   --
   -- If the connection has been fully Shutdown, Program_Error is raised.
   --
   -- If Re_secure fails, the connection is shutdown, and an exception is
   -- always propegated.
 
   ------------------
   -- TLS_Listener --
   ------------------
   
   type TLS_Listener 
     (Queue_Size   : Positive;
      Configuration: not null access TLS_Server_Configuration'Class)
     is limited new TCP_Listener with private;
   
   -- Note that sessions can stil be managed separately via the Configuration
   -- object, even while the listener is live (Bound)
   
   overriding
   procedure Bind (Listener: in out TLS_Listener;
                   Address : in     IP.IP_Address;
                   Port    : in     TCP_Port);
   
   -- Note that Clear_Keys may be invoked on Configuration after all
   -- TLS_Listener objects that depend on it have been successfully
   -- Bound. In other words, Bind is what establishes the listener context,
   -- and is therefore that moment that the keys are copied to that
   -- context.
   
   overriding
   procedure Dequeue (Listener  : in out TLS_Listener;
                      Connection: in out TCP_Connection'Class)
   with Pre => Connection in TLS_Server_Connection'Class;
   
   overriding
   function Dequeue (Listener: in out TLS_Listener) return TCP_Connection'Class
   with Post'Class => Dequeue'Result in TLS_Server_Connection'Class
                      and then TLS_Connection'Class (Dequeue'Result).Secured;
   
   -- Dequeues an established TLS_Server_Connection object from a TLS_Listener.
   -- The dequeued TLS_Server_Connection will be secured, and ready for use.
   --
   -- To negotiate plain-text protocols before initiating TLS, a TCP_Listener
   -- that is not a member of TLS_Listener'Class should be used to dequeue to
   -- a TLS_Server_Connection object. See TLS_Server_Connection.Secure, above.
   --
   -- If using the procedure, if Connection is connected (secured or not), it
   -- is first closed
   
private
   
   type TLS_Connection is
     limited new TCP.TCP_Connection with
      record
         Context: INET.Internal.TLS.TLS_Stream_Context;
         TLS_Go: Boolean := False;
         -- Set to True only if the connection and handshake attempt is
         -- reported successful by libtls. This value must be True
         -- for Reads or Writes to be allowed.
         
         Read_Down, Write_Down: Boolean := False;
         -- Used to track the use of Shutdown_Read/_Write. See the
         -- comments for Shutdown above for more information.
      end record;
   
   -- All a TLS Connection really needs is a context. The context is sufficent
   -- to send and receive, and to manage the state of the connection. Contexts
   -- are created during Connect, Secure, or when Dequeing from a TLS_Listener 
   -- object Contexts are reset if possible, making it possible for the
   -- underlying libtls to re-use memory, however this appears to be unlikely.
   
   type TLS_Client_Connection 
     (Configuration: not null access TLS_Client_Configuration'Class) 
     is limited new TLS_Connection with null record;
   
   type TLS_Server_Connection is limited new TLS_Connection with null record;
   
   ------------------
   -- TLS_Listener --
   ------------------
   
   type TLS_Listener 
     (Queue_Size   : Positive;
      Configuration: not null access TLS_Server_Configuration'Class)
     is limited new TCP_Listener (Queue_Size) with
      record
         Context: INET.Internal.TLS.TLS_Listener_Context;
      end record;
   
end INET.TCP.TLS;
