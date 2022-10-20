------------------------------------------------------------------------------
--                                                                          --
--                    Internet Protocol Suite Package                       --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2020-2022, ANNEXI-STRAYLINE Trans-Human Ltd.              --
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

with Ada.IO_Exceptions;

with INET.IP.Lookup;
with INET.Internal.UNIX_Sockets;

package body INET.TCP.TLS is
   
   End_Error: exception renames Ada.IO_Exceptions.End_Error;
   
   --
   -- TLS_Connection
   --
   
   -------------
   -- Secured --
   -------------
   
   function Secured (Connection: TLS_Connection) return Boolean is
     (Connection.TLS_Go);
   
   ----------
   -- Read --
   ----------
   
   procedure Receive_Immediate_Wrapper
     (Connection: in out TLS_Connection;
      Buffer    :    out Stream_Element_Array;
      Last      :    out Stream_Element_Offset;
      Status    :    out INET.Internal.UNIX_Sockets.Operation_Status;
      Errno     :    out Interfaces.C.int)
   with Inline is
      use INET.Internal.UNIX_Sockets;
   begin
      if not Connection.TLS_Go then
         raise Program_Error with
           "Attempt to Read from an unsecured TLS_Connection";
      elsif Connection.Read_Down then
         raise End_Error with "TLS: Read direction has been shutdown";
      end if;
      
      Connection.Context.TLS_Receive_Immediate
        (Buffer => Buffer,
         Last   => Last);
      
      Status := OK;
      Errno  := 0;
      
      -- These are really specific to the "standard" implementation in INET.TCP
      -- which we are borrowing. In the case of TLS, if something goes wrong,
      -- it is usually pretty catestrophic, so we just propegate the exception
      -- as it arrives. If we get here, everything appears to be normal.
      
   end Receive_Immediate_Wrapper;
   
   ----------------------------------------------------------------------
   
   procedure Read_Actual is new Generic_Read
     (Connection_Type              => TLS_Connection,
      Connection_Receive_Immediate => Receive_Immediate_Wrapper);
   
   procedure Read (Stream: in out TLS_Connection;
                   Item  :    out Stream_Element_Array;
                   Last  :    out Stream_Element_Offset)
     renames Read_Actual;
   
   --------------------
   -- Read_Immediate --
   --------------------
   
   procedure Read_Immediate (Stream: in out TLS_Connection;
                             Item  :    out Stream_Element_Array;
                             Last  :    out Stream_Element_Offset)
   is begin
      if not Stream.TLS_Go then
         raise Program_Error with
           "Attempt to Read from an unsecured TLS_Connection";
      elsif Stream.Read_Down then
         raise End_Error with "TLS: Read direction has been shutdown";
      end if;
      
      Stream.Context.TLS_Receive_Immediate (Buffer => Item,
                                            Last   => Last);
   end Read_Immediate;
   
   -----------
   -- Write --
   -----------
   
   procedure Send_Immediate_Wrapper
     (Connection: in out TLS_Connection;
      Buffer    : in     Stream_Element_Array;
      Last      :    out Stream_Element_Offset;
      Status    :    out INET.Internal.UNIX_Sockets.Operation_Status;
      Errno     :    out Interfaces.C.int)
   with Inline is
      use INET.Internal.UNIX_Sockets;
   begin
      if not Connection.TLS_Go then
         raise Program_Error with
           "Attempt to Write to an unsecured TLS_Connection";
      elsif Connection.Write_Down then
         raise End_Error with "TLS: Write direction has been shutdown";
      end if;
      
      Connection.Context.TLS_Send_Immediate
        (Buffer => Buffer,
         Last   => Last);
      
      Status := OK;
      Errno  := 0;
      
      -- These are really specific to the "standard" implementation in INET.TCP
      -- which we are borrowing. In the case of TLS, if something goes wrong,
      -- it is usually pretty catestrophic, so we just propegate the exception
      -- as it arrives. If we get here, everything appears to be normal.
      
   end Send_Immediate_Wrapper;
   
   ----------------------------------------------------------------------
   
   procedure Write_Actual is new Generic_Write
     (Connection_Type           => TLS_Connection,
      Connection_Send_Immediate => Send_Immediate_Wrapper);
   
   procedure Write (Stream: in out TLS_Connection;
                    Item  : in     Stream_Element_Array)
     renames Write_Actual;
   
   ---------------------
   -- Write_Immediate --
   ---------------------
   
   procedure Write_Immediate (Stream: in out TLS_Connection;
                              Item  : in     Stream_Element_Array;
                              Last  :    out Stream_Element_Offset)
   is begin
      if not Stream.TLS_Go then
         raise Program_Error with
           "Attempt to Write to an unsecured TLS_Connection";
      elsif Stream.Write_Down then
         raise End_Error with "TLS: Write direction has been shutdown";
      end if;
      
      Stream.Context.TLS_Send_Immediate (Buffer => Item,
                                         Last   => Last);
   end Write_Immediate;
   
   --------------
   -- Shutdown --
   --------------
   
   procedure Shutdown (Connection: in out TLS_Connection) is
   begin
      Connection.Context.Shutdown;
      TCP_Connection(Connection).Shutdown;
      Connection.TLS_Go     := False;
      Connection.Read_Down  := True;
      Connection.Write_Down := True;
      
   exception
      when TLS_Error => null;
         -- Sometimes the remote peer closes the connection without a close
         -- notify. We do not want to propegate this out when we shutdown
   end Shutdown;
   
   -------------------
   -- Shutdown_Read --
   -------------------
   
   procedure Shutdown_Read (Connection: in out TLS_Connection) is
   begin
      if Connection.Write_Down then
         Connection.Shutdown;
      else
         Connection.Read_Down := True;
      end if;
   end Shutdown_Read;
   
   --------------------
   -- Shutdown_Write --
   --------------------
   
   procedure Shutdown_Write (Connection: in out TLS_Connection) is
   begin
      if Connection.Read_Down then
         Connection.Shutdown;
      else
         Connection.Write_Down := True;
      end if;
   end Shutdown_Write;
   
   --
   -- TLS_Client_Connection
   --
   
   -------------
   -- Connect --
   -------------
   
   procedure Connect_Actual (Connection : in out TLS_Client_Connection;
                             Address    : in     IP.IP_Address;
                             Port       : in     TCP_Port;
                             Server_Name: in     String)
   with Inline is
   begin
      Connection.Shutdown;
      TCP_Connection (Connection).Connect (Address, Port);
      Connection.TLS_Go     := False;
      Connection.Read_Down  := False;
      Connection.Write_Down := False;
      Connection.Secure (Server_Name);
   exception
      when others =>
         Connection.Shutdown;
         raise;
   end Connect_Actual;
   
   ----------------------------------------------------------------------
   
   procedure Connect (Connection: in out TLS_Client_Connection;
                      Address   : in     IP.IP_Address;
                      Port      : in     TCP_Port)
   is begin
      raise Program_Error with 
        "TLS client connections must provide a host name for the remote peer.";
   end;
   
   ----------------------------------------------------------------------
   
   procedure Connect (Connection : in out TLS_Client_Connection;
                      Address    : in     IP.IP_Address;
                      Port       : in     TCP_Port;
                      Server_Name: in     String)
   is begin
      if Server_Name'Length = 0 then
         raise Constraint_Error with
           "SNI Server name must not be an empty string.";
      end if;
      
      Connect_Actual (Connection, Address, Port, Server_Name);
   end;
   
   ----------------------------------------------------------------------
   
   overriding
   procedure Connect (Connection: in out TLS_Client_Connection;
                      Host_Name : in     String;
                      Port      : in     TCP_Port)
   is
      use INET.IP.Lookup;
      
      Query : IP_Lookup;
      Result: IP_Lookup_Entry;
   begin
      Query.Lookup (Host_Name => Host_Name,
                    Protocol  => Proto_TCP);
      
      if not Query.Has_More_Entries then
         raise TCP_Lookup_Failed with "Lookup of host """
           & Host_Name & """ failed.";
      end if;
      
      Query.Pop (Result);
      Connection.Connect (Address     => Result.Address,
                          Port        => Port,
                          Server_Name => Host_Name);
   end Connect;
   
   ----------------------------------------------------------------------
   
   overriding
   procedure Connect (Connection   : in out TLS_Client_Connection;
                      Host_Name    : in     String;
                      Port         : in     TCP_Port;
                      Version      : in     IP.IP_Version)
   is
      use INET.IP.Lookup;
      
      Query : IP_Lookup;
      Result: IP_Lookup_Entry;
   begin
      Query.Lookup (Host_Name => Host_Name,
                    Protocol  => Proto_TCP,
                    Version   => Version);
      
      if not Query.Has_More_Entries then
         raise TCP_Lookup_Failed with "Lookup of host """
           & Host_Name & """ failed.";
      end if;
      
      Query.Pop (Result);
      Connection.Connect (Address     => Result.Address,
                          Port        => Port,
                          Server_Name => Host_Name);
   end Connect;
   
   ------------
   -- Secure --
   ------------
   
   procedure Secure
     (Connection : in out TLS_Client_Connection;
      Server_Name: in     String) 
   is begin
      if Server_Name'Length = 0 then
         raise Constraint_Error with
           "SNI Server name must not be an empty string.";
         
      elsif Connection.Write_Down and Connection.Read_Down then
         raise Program_Error with
           "Secure cannot be invoked on a shutdown connection.";
         
      elsif Connection.TLS_Go then
         Connection.Context.Handshake (Socket  => Connection.Socket,
                                       Timeout => Explicit_Handshake_Timeout);
      else
         pragma Assert (not Connection.Context.Available);
         
         if Server_Name'Length > 0 then
            Connection.Context.Establish 
              (Configuration => Connection.Configuration.all,
               Server_Name   => Server_Name,
               Socket        => Connection.Socket,
               Timeout       => Explicit_Handshake_Timeout);
            
         else
            Connection.Context.Establish 
              (Configuration => Connection.Configuration.all,
               Socket        => Connection.Socket,
               Timeout       => Explicit_Handshake_Timeout);
         end if;
         
         Connection.TLS_Go     := True;
         Connection.Read_Down  := False;
         Connection.Write_Down := False;
      end if;
   exception
      when others =>
         Connection.Shutdown;
         raise;
   end Secure;
   
   --
   -- TLS_Server_Connection
   --
   
   -------------
   -- Connect --
   -------------
   
   procedure No_Connect with Inline, No_Return is
   begin
      raise Program_Error with
        "Connect not allowed on TLS_Server_Connection objects.";
   end;
   
   ----------------------------------------------------------------------
   
   procedure Connect (Connection: in out TLS_Server_Connection;
                      Address   : in     IP.IP_Address;
                      Port      : in     TCP_Port)
   is begin
      No_Connect;
   end;
   
   ----------------------------------------------------------------------
   
   procedure Connect (Connection: in out TLS_Server_Connection;
                      Host_Name : in     String;
                      Port      : in     TCP_Port)
   is begin
      No_Connect;
   end;
   
   ----------------------------------------------------------------------
   
   procedure Connect (Connection   : in out TLS_Server_Connection;
                      Host_Name    : in     String;
                      Port         : in     TCP_Port;
                      Version      : in     IP.IP_Version)
   is begin
      No_Connect;
   end;
   
   ------------
   -- Secure --
   ------------
   
   procedure Secure (Connection   : in out TLS_Server_Connection;
                     Configuration: in     TLS_Server_Configuration'Class)
   is 
      -- This one is a bit unusual, since we need to make a single-use
      -- TLS_Listener_Context, since libtls needs that to generate a
      -- context for a server-side connection. This is part of the reason
      -- why already Secured TLS_Server_Connections are not allowed.
      --
      -- Normally, with a TLS_Listener.Dequeue, we'd use that as the
      -- listener. 
      --
      -- This Secure is specifically here to allow for negotiated upgrades
      -- to TLS, such as in SMTP with STARTTLS
      
      Source_Context: INET.Internal.TLS.TLS_Listener_Context;
   begin
      if Connection.Write_Down and Connection.Read_Down then
         raise Program_Error with
           "Secure cannot be invoked on a shutdown connection.";
         
      elsif Connection.TLS_Go then
         raise Program_Error with
           "Secure cannot be invoked on Secured TLS_Server_Connection "
           & "objects. ";
      end if;
      
      Source_Context.Configure (Configuration);
      Connection.Context.Establish
        (Listener_Context => Source_Context,
         Socket           => Connection.Socket,
         Timeout          => Explicit_Handshake_Timeout);
      Connection.TLS_Go     := True;
      Connection.Read_Down  := False;
      Connection.Write_Down := False;
      
   exception
      when others =>
         Connection.Shutdown;
         raise;
   end Secure;
   
   ---------------
   -- Re_Secure --
   ---------------
   
   procedure Re_secure (Connection: in out TLS_Server_Connection) is
   begin
      if Connection.Write_Down and Connection.Read_Down then
         raise Program_Error with
           "Re_Secure cannot be invoked on a shutdown connection.";
      elsif not Connection.TLS_Go then
         raise Program_Error with
           "Re_Secure cannot be invoked unless the TLS_Server_Connection "
           & "object is already Secured";
      end if;
      
      Connection.Context.Handshake (Socket  => Connection.Socket,
                                    Timeout => Explicit_Handshake_Timeout);
      
   exception
      when others =>
         Connection.Shutdown;
         raise;
   end Re_Secure;
   
   --
   -- TLS_Listener
   --
   
   ----------
   -- Bind --
   ----------
   
   procedure Bind (Listener: in out TLS_Listener;
                   Address : in     IP.IP_Address;
                   Port    : in     TCP_Port)
   is begin
      TCP_Listener (Listener).Bind (Address, Port);
      Listener.Context.Configure (Listener.Configuration.all);
   end Bind;
   
   -------------
   -- Dequeue --
   -------------
   
   procedure Dequeue (Listener  : in out TLS_Listener;
                      Connection: in out TCP_Connection'Class)
   is 
   begin
      if Connection not in TLS_Server_Connection'Class then
         raise Program_Error with
           "TLS_Listener.Dequeue must be target an object of "
           & "TLS_Server_Connection'Class only.";
      end if;
      
      Connection.Shutdown;
      TCP_Listener (Listener).Dequeue (Connection);
      
      declare
         TLS_Connection: TLS_Server_Connection'Class
           renames TLS_Server_Connection'Class (Connection);
      begin
         TLS_Connection.Context.Establish
           (Listener_Context => Listener.Context,
            Socket           => TLS_Connection.Socket,
            Timeout          => Explicit_Handshake_Timeout);
         
         TLS_Connection.TLS_Go     := True;
         TLS_Connection.Read_Down  := False;
         TLS_Connection.Write_Down := False;
         
      exception
         when others =>
            TLS_Connection.Shutdown;
            raise;
      end;
   end Dequeue;
   
   ----------------------------------------------------------------------
   
   -- GNAT Bug work-around --
   -- GNAT doesn't handle extended returns of class-wide types very well.
   -- We need an intermediate function that returns the specific type,
   -- and then return that result.
   
   function Intermediate_Dequeue (Listener: in out TLS_Listener)
                                 return TLS_Server_Connection
   with Inline is
   begin
      return New_Connection: TLS_Server_Connection do
         Listener.Dequeue (New_Connection);
      end return;
   end Intermediate_Dequeue;
   
   
   function Dequeue (Listener: in out TLS_Listener) return TCP_Connection'Class
   is (Intermediate_Dequeue (Listener));
   
end INET.TCP.TLS;
