------------------------------------------------------------------------------
--                                                                          --
--                    Internet Protocol Suite Package                       --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2020-2024 ANNEXI-STRAYLINE Inc.                           --
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
with Ada.Exceptions;
with Interfaces.C;

with INET.IP.Lookup;

package body INET.TCP is
   
   use type Interfaces.C.int;
   subtype int is Interfaces.C.int;
   
   function Exception_Information (X: Ada.Exceptions.Exception_Occurrence)
                                  return String
     renames Ada.Exceptions.Exception_Information;
   
   
   ------------------------
   -- Raise_IO_Exception --
   ------------------------
      
   -- Given an Operation_Status value, raises the appropriate exception.
      
   procedure Raise_IO_Exception (Status: in UNIX_Sockets.Operation_Status;
                                 Errno : in int)
   is
      use UNIX_Sockets;
      
   begin
      case Status is
         when OK | Not_Ready     => null;
         when Timedout           => raise TCP_Timeout;
            
         when Not_Connected => 
            -- This only means the user is trying read/write before creating a
            -- connection
            raise Program_Error with "TCP_Connection must be connected first.";
            
         when Connection_Reset   => raise TCP_Connection_Reset;
         when Connection_Refused => raise TCP_Connection_Refused;
         when Net_Unreachable    => raise TCP_Net_Unreachable;
         when Host_Unreachable   => raise TCP_Host_Unreachable;
            
         when Unauthorized
           |  Address_Occupied => 
            raise TCP_System_Error with "Operation_Status """
              & Operation_Status'Image (Status)
              & """ not expected during send/recv.";
            
         when Other_Failure =>
            raise TCP_System_Error with " errno =" & int'Image (Errno);
      end case;
   end Raise_IO_Exception;
   
   --
   -- TCP_Connection
   --
   
   ----------------------
   -- Generic_Poll_Set --
   ----------------------
   
   generic
      Stream     : in out TCP_Connection'Class;
      Direction  : in     UNIX_Sockets.Data_Direction;
      Timeout_Set: in     Boolean;
      Timeout    : in     Duration;
      Start_Time : in     Ada.Calendar.Time;
      -- Should point at Socket.Read_Block or Write_Block;
      
   package Generic_Poll_Set is
      
      procedure Poll_With_Timeout with Pre => Timeout_Set;
      -- Poll_With_Timeout is only invoked if the connection has a timeout set
      -- Therefore it also takes responsibility for raising a TCP_Timeout
      -- exception if the timout is exceeded.
      
      procedure Poll_Forever with Pre => not Timeout_Set;
      -- In this case, we don't give a timeout at all, but it may still
      -- might get interrupted. The Generic_Transfer_Loop implementation
      -- deals with that condition
      
   end Generic_Poll_Set;
   
   package body Generic_Poll_Set is
      
      use Ada.Calendar;
      
      procedure Poll_With_Timeout is
         Elapsed_Time  : constant Duration := Clock - Start_Time;
      begin
         -- Check for a timeout expirty before executing a poll.
         if Elapsed_Time >= Stream.Read_Timeout then
            raise TCP_Timeout;
         end if;
         
         -- This means that Elapsed_Time < Stream.Read_Timeout.
         -- This assertion would be checked by the precondition on Wait.
         
         UNIX_Sockets.Wait (Socket    => Stream.Socket,
                            Direction => Direction,
                            Timeout   => Timeout - Elapsed_Time);
         
      end Poll_With_Timeout;
      
      
      procedure Poll_Forever is
         -- In this case, we don't give a timeout at all, but it may still
         -- get "interrupted", but that won't concern us. The key is that
         -- we won't leave the main loop until Last = Item'Last.
      begin
         UNIX_Sockets.Wait (Socket    => Stream.Socket,
                            Direction => Direction);
      end Poll_Forever;
      
   end Generic_Poll_Set;
   
   
   ------------------
   -- Generic_Read --
   ------------------
   
   procedure Generic_Read (Stream: in out Connection_Type;
                           Item  :    out Stream_Element_Array;
                           Last  :    out Stream_Element_Offset)
   is 
      use UNIX_Sockets;
      
      Status: Operation_Status;
      Errno : int;
      
      Water_Level: Stream_Element_Offset := Item'First - 1;
      -- Index of the most recently received storage element
      
      package Poll_Set is new Generic_Poll_Set
        (Stream      => TCP_Connection'Class(Stream),
         Direction   => Inbound,
         Timeout_Set => Stream.Read_Does_Timeout,
         Timeout     => Stream.Read_Timeout,
         Start_Time  => Ada.Calendar.Clock);

      -- Select the appropriate polling procedure
      Poll: access procedure;
      
      Did_One_Poll: Boolean := False;
      
   begin
      if Item'Length = 0 then
         Last := Item'Last;
         return;
      end if;
      
      if Stream.Read_Does_Timeout then
         if Stream.Read_Timeout = 0.0 then
            -- This is just the same as a Read_Immediate.
            Stream.Read_Immediate (Item, Last);
            return;
            
         else
            Poll := Poll_Set.Poll_With_Timeout'Access;
         end if;
      else
         Poll := Poll_Set.Poll_Forever'Access;
         
      end if;
      
      loop
         Connection_Receive_Immediate 
           (Connection => Stream,
            Buffer     => Item (Water_Level + 1 .. Item'Last),
            Last       => Last,
            Status     => Status,
            Errno      => Errno);
         
         exit when Last = Item'Last;
         -- If we got everything, even if there was an error, there's no real
         -- reason to report it, thus this comes before we check status
         
         if Status not in OK | Not_Ready then
            Raise_IO_Exception (Status, Errno);
         elsif Last = Water_Level
           and then Did_One_Poll
         then
            -- If a poll returned normally the poll therefore indicated that
            -- data is available. If we then find the we receive nothing, this
            -- is the BSD sockets way of saying the connection was closed,
            -- or more correctly that we have reached the actual end of the
            -- data (communication completed 'normally').
            return;
         end if;
         
         if Last > Water_Level then
            Water_Level := Last;
         end if;
         
         -- We don't have enough and we didn't get an explicit error. Time to
         -- sleep on it
         Poll.all;
         
         Did_One_Poll := True;
         
      end loop;
   end Generic_Read;
   
   -------------------
   -- Generic_Write --
   -------------------
   
   procedure Generic_Write (Stream: in out Connection_Type;
                            Item  : in     Stream_Element_Array)
   is
      use UNIX_Sockets;
      
      Status: Operation_Status;
      Errno : int;
      
      Water_Level: Stream_Element_Offset := Item'First - 1;
      Last       : Stream_Element_Offset;
      -- Index of the most recently sent storage element
      
      package Poll_Set is new Generic_Poll_Set
        (Stream      => TCP_Connection'Class(Stream),
         Direction   => Outbound,
         Timeout_Set => Stream.Write_Does_Timeout,
         Timeout     => Stream.Write_Timeout,
         Start_Time  => Ada.Calendar.Clock);

      -- Select the appropriate polling procedure
      Poll: access procedure;
      
   begin
      if Item'Length = 0 then
         return;
      end if;
      
      if Stream.Write_Does_Timeout then
         if Stream.Write_Timeout = 0.0 then
            -- This is just the same as a Wirte_Immediate, however we
            -- need to raise an exception if Last is < Item'Last.
            
            Stream.Write_Immediate (Item, Last);
            
            if Last < Item'Last then
               -- This implies the write was OK, or Not_Ready, otherwise
               -- Write_Immediate would have raised an exception.
               
               raise TCP_Timeout with "INET.TCP.Write: "
                 & "TCP_Connection is set to non-blocking, but "
                 & "the write could not be completed.";
            end if;
            
         else
            Poll := Poll_Set.Poll_With_Timeout'Access;
            
         end if;
         
      else
         Poll := Poll_Set.Poll_Forever'Access;
         
      end if;
         
      loop
         Connection_Send_Immediate 
           (Connection => Stream,
            Buffer     => Item (Water_Level + 1 .. Item'Last),
            Last       => Last,
            Status     => Status,
            Errno      => Errno);
         
         exit when Last = Item'Last;
         -- If we got everything, even if there was an error, there's no real
         -- reason to report it, thus this comes before we check status
         
         if Status not in OK | Not_Ready then
            Raise_IO_Exception (Status, Errno);
         end if;
         
         if Last > Water_Level then
            Water_Level := Last;
         end if;
         
         -- We don't have enough and we didn't get an explicit error. Time to
         -- sleep on it
         Poll.all;
         
      end loop;
   end Generic_Write;
   
   ----------
   -- Read --
   ----------
   
   procedure Receive_Immediate_Wrapper
     (Connection: in out TCP_Connection;
      Buffer    :    out Stream_Element_Array;
      Last      :    out Stream_Element_Offset;
      Status    :    out UNIX_Sockets.Operation_Status;
      Errno     :    out int)
   with Inline is 
      use UNIX_Sockets; 
   begin
      TCP_Receive_Immediate (Socket => Connection.Socket,
                             Buffer => Buffer,
                             Last   => Last,
                             Status => Status,
                             Errno  => Errno);
   end;
   
   procedure Read_Actual is new Generic_Read 
     (Connection_Type              => TCP_Connection,
      Connection_Receive_Immediate => Receive_Immediate_Wrapper);
   
   procedure Read (Stream: in out TCP_Connection;
                   Item  :    out Stream_Element_Array;
                   Last  :    out Stream_Element_Offset)
     renames Read_Actual;
   
   --------------------
   -- Read_Immediate --
   --------------------
   
   procedure Read_Immediate (Stream: in out TCP_Connection;
                             Item  :    out Stream_Element_Array;
                             Last  :    out Stream_Element_Offset)
   is
      use UNIX_Sockets;
      
      Status: Operation_Status;
      Errno : int;
   begin
      TCP_Receive_Immediate (Socket    => Stream.Socket,
                             Buffer    => Item,
                             Last      => Last,
                             Status    => Status,
                             Errno     => Errno);
      
      -- We don't really "care" if that worked or not..
      
   end Read_Immediate;
   
   -----------
   -- Write --
   -----------
   
   procedure Send_Immediate_Wrapper
     (Connection: in out TCP_Connection;
      Buffer    : in     Stream_Element_Array;
      Last      :    out Stream_Element_Offset;
      Status    :    out UNIX_Sockets.Operation_Status;
      Errno     :    out int)
   with Inline is
      use UNIX_Sockets;
   begin
      TCP_Send_Immediate (Socket => Connection.Socket,
                          Buffer => Buffer,
                          Last   => Last,
                          Status => Status,
                          Errno  => Errno);
   end;
   
   procedure Write_Actual is new Generic_Write
     (Connection_Type           => TCP_Connection,
      Connection_Send_Immediate => Send_Immediate_Wrapper);
   
   procedure Write (Stream: in out TCP_Connection;
                    Item  : in     Stream_Element_Array)
     renames Write_Actual;
   
   ---------------------
   -- Write_Immediate --
   ---------------------
   
   procedure Write_Immediate (Stream: in out TCP_Connection;
                              Item  : in     Stream_Element_Array;
                              Last  :    out Stream_Element_Offset)
   is
      use UNIX_Sockets;
      
      Status: Operation_Status;
      Errno : int;
   begin
      TCP_Send_Immediate (Socket    => Stream.Socket,
                          Buffer    => Item,
                          Last      => Last,
                          Status    => Status,
                          Errno     => Errno);
   end Write_Immediate;
   
   -------------------------
   -- Destination_Address --
   -------------------------
   
   function  Destination_Address (Connection: TCP_Connection) 
                                 return IP.IP_Address is
     (Connection.Destination_Address);
   
   ----------------------
   -- Destination_Port --
   ----------------------
   
   function  Destination_Port (Connection: TCP_Connection) 
                              return TCP_Port is
     (Connection.Destination_Port);
   
   ------------------
   -- Read_Timeout --
   ------------------
   
   procedure Read_Timeout  (Connection: in out TCP_Connection; 
                            Timeout   : in     Duration)
   is begin
      Connection.Read_Does_Timeout := True;
      Connection.Read_Timeout      := Timeout;
   end Read_Timeout;
   
   ------------------------
   -- Read_Never_Timeout --
   ------------------------
   
   procedure Read_Never_Timeout (Connection: in out TCP_Connection) is
   begin
      Connection.Read_Does_Timeout := False;
   end Read_Never_Timeout;
   
   
   -------------------
   -- Write_Timeout --
   -------------------
   
   procedure Write_Timeout  (Connection: in out TCP_Connection; 
                             Timeout   : in     Duration)
   is begin
      Connection.Write_Does_Timeout := True;
      Connection.Write_Timeout      := Timeout;
   end Write_Timeout;
   
   -------------------------
   -- Write_Never_Timeout --
   -------------------------
   
   procedure Write_Never_Timeout (Connection: in out TCP_Connection) is
   begin
      Connection.Write_Does_Timeout := False;
   end Write_Never_Timeout;
   
   -------------
   -- Connect --
   -------------
   
   procedure Connect (Connection: in out TCP_Connection;
                      Address   : in     IP.IP_Address;
                      Port      : in     TCP_Port)
   is
      use UNIX_Sockets;
      
      Status: Operation_Status;
      Errno : int;
   begin
      TCP_Connect (Socket  => Connection.Socket,
                   Address => Address,
                   Port    => Port,
                   Status  => Status,
                   Errno   => Errno);
      
      if Status = OK then
         Connection.Destination_Address := Address;
         Connection.Destination_Port    := Port;
      else
         pragma Assert (Status /= Not_Connected);
         -- This would not make sense..
         
         Raise_IO_Exception (Status, Errno);
      end if;
   end Connect;
   
   ----------------------------------------------------------------------
   
   procedure Connect (Connection: in out TCP_Connection;
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
      Connection.Connect (Address => Result.Address,
                          Port    => Port);
   end Connect;
   
   ----------------------------------------------------------------------
   
   procedure Connect (Connection   : in out TCP_Connection;
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
      Connection.Connect (Address => Result.Address,
                          Port    => Port);
   end Connect;
   
   --------------
   -- Shutdown --
   --------------
   
   procedure Shutdown (Connection: in out TCP_Connection) is
      use UNIX_Sockets;
   begin
      TCP_Shutdown (Socket    => Connection.Socket,
                    Direction => Both);
   end Shutdown;
   
   -------------------
   -- Shutdown_Read --
   -------------------
   
   procedure Shutdown_Read  (Connection: in out TCP_Connection) is
      use UNIX_Sockets;
   begin
      TCP_Shutdown (Socket    => Connection.Socket,
                    Direction => Inbound);
   end Shutdown_Read;
   
   --------------------
   -- Shutdown_Write --
   --------------------
   
   procedure Shutdown_Write  (Connection: in out TCP_Connection) is
      use UNIX_Sockets;
   begin
      TCP_Shutdown (Socket    => Connection.Socket,
                    Direction => Outbound);
   end Shutdown_Write;
   
   --
   -- TCP_Listener
   --
   
   -------------------------
   -- Listener_Bound_Flag --
   -------------------------
   
   protected body Listener_Bound_Flag is
      
      procedure Set_Bound is begin
         pragma Assert (Bound_Flag = False);
         Bound_Flag := True;
      end;
   
      function Is_Bound return Boolean is (Bound_Flag);
      
   end Listener_Bound_Flag;
   
   --------------
   -- Is_Bound --
   --------------
   
   function Is_Bound (Listener: TCP_Listener) return Boolean is
     (Listener.Bound_Flag.Is_Bound);
   
   ----------
   -- Bind --
   ----------
   
   procedure Bind (Listener: in out TCP_Listener;
                   Address : in     IP.IP_Address;
                   Port    : in     TCP_Port)
   is
      use UNIX_Sockets;
      
      Result: Operation_Status;
      Errno : int;
   begin
      if Listener.Bound_Flag.Is_Bound then
         raise Program_Error with "Attempt to Bind a TCP_Listener twice.";
      end if;
      
      TCP_Bind_Listener (Socket  => Listener.Socket,
                         Address => Address,
                         Port    => Port,
                         Backlog => Listener.Queue_Size,
                         Status  => Result,
                         Errno   => Errno);
      
      case Result is
         when OK =>
            null;
            
         when Unauthorized =>
            raise TCP_Bind_Unauthorized;
            
         when Address_Occupied =>
            raise TCP_Bind_Occupied;
            
         when others =>
            raise TCP_System_Error with
              "Bind failed with status: " 
              & Operation_Status'Image (Result)
              & " (errno =" & int'Image (Errno) & ')';
            
      end case;
      
      -- Done
      Listener.Bound_Flag.Set_Bound;
      
   exception
      when Program_Error 
        |  TCP_System_Error 
        |  TCP_Bind_Unauthorized 
        |  TCP_Bind_Occupied 
        =>
         raise;
         
      when e: others =>
         raise TCP_System_Error with "Unexpected exception: " 
           & Exception_Information (e);
   end Bind;
   
   -------------
   -- Dequeue --
   -------------
   
   procedure Dequeue (Listener  : in out TCP_Listener;
                      Connection: in out TCP_Connection'Class)
   is
      use UNIX_Sockets;
      
      Status: Operation_Status;
      Errno : int;
   begin
      if not Listener.Is_Bound then
         raise TCP_Listener_Not_Bound;
      end if;
         
      Connection.Shutdown;
      -- The socket will be closed and replaced within the UNIX_Sockets
      -- package, if it is active
      
      TCP_Accept_Connection (Listen_Socket  => Listener.Socket,
                             New_Socket     => Connection.Socket,
                             Client_Address => Connection.Destination_Address,
                             Client_Port    => Connection.Destination_Port,
                             Status         => Status,
                             Errno          => Errno);
      
      if Status /= OK then
         raise TCP_System_Error with
           "Dequeue failed with status: " 
           & Operation_Status'Image (Status)
           & " (errno =" & int'Image (Errno) & ')';
      end if;
   end Dequeue;
   
   ----------------------------------------------------------------------
   
   -- GNAT Bug work-around --
   -- GNAT doesn't handle extended returns of class-wide types very well.
   -- We need an intermediate function that returns the specific type,
   -- and then return that result.
   
   function Intermediate_Dequeue (Listener: in out TCP_Listener)
                                 return TCP_Connection
   with Inline is
   begin
      return New_Connection: TCP_Connection do
         Listener.Dequeue (New_Connection);
      end return;
   end Intermediate_Dequeue;
   
   
   function Dequeue (Listener: in out TCP_Listener) return TCP_Connection'Class
   is (Intermediate_Dequeue (Listener));
   
end INET.TCP;
