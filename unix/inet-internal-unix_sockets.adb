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
--  * Ensi Martini (ANNEXI-STRAYLINE)                                       --
--  * Richard Wai  (ANNEXI-STRAYLINE)                                       --
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

with Interfaces.C.Strings;

with AURA;

with INET.IP;
with INET.TCP;
with INET.Internal.OS_Constants; use INET.Internal.OS_Constants;

pragma External_With ("inet-internal-unix_sockets-sys.c");

package body INET.Internal.UNIX_Sockets is
   
   function close (fd: int) return int with
     Convention    => C,
     Import        => True,
     External_Name => "close";
   -- close(2) - libc
   
   function create_socket 
     (domain: int; sock_type: int; protocol: int := 0) return int 
   with
     Convention    => C,
     Import        => True,
     External_Name => "socket";
   -- socket(2) - libc
   
   function set_nonblocking (fd: int) return int with
     Convention    => C,
     Import        => True,
     External_Name => "__inet_internal_unix_sockets_sys_set_nonblocking";
   
   -- Just a call to fcntl underneath. Unfortunately fcntl is a varargs
   -- function, so just to ensure compatibility, we'll put it in the binding
   --
   -- Returns -1 on failure
   
   procedure block_sigpipe with
     Convention => C,
     Import => True,
     External_Name => "__inet_internal_unix_sockets_sys_block_sigpipe";
   
   -- Invoked by the package elaboration code of this package. Ensures that
   -- SIGPIPES do not show up - since they will silently terminate the process.
   -- Though we block signals on write here, other extensions (TLS!) write to
   -- their sockets directly, and don't block sigpipe, which is a big problem!
   
   ------------------
   -- Errno_Status --
   ------------------
   
   -- Reads and converts the value for "errno" into the appropriate
   -- Operation_Status value, and returns the value for "errno"
   
   procedure Errno_Status (Errno : out int;
                           Status: out Operation_Status)
                           
   is
      procedure Convert_Errno (Status_Pos: out int;
                               Errno     : out int)
      with Convention => C, Import => True,
        External_Name => "__inet_internal_unix_sockets_sys_convert_errno";
      
      -- Returns a position that should be valid for Operation_Status, based
      -- on the current errno value, and also returns that value
      
      Status_Pos: int;
   begin
      Convert_Errno (Status_Pos, Errno);
      Status := Operation_Status'Val (Status_Pos);
   exception
      when others =>
         Status := Other_Failure;
   end Errno_Status;
   
   -------------------
   -- Socket_Active --
   -------------------
   
   function Socket_Active (Socket: UNIX_Socket) return Boolean is
     (case Socket.Protocol is
         when TCP => Socket.TCP_Socket /= Invalid_Descriptor,
         when UDP => True);
   
   ----------------
   -- Initialize --
   ----------------
   
   procedure Initialize (Socket : in out UNIX_Socket) is
      use INET.IP;
      
      Flags: constant int := (if AURA.Platform_Flavor = "darwin" then 
                                 0
                              else
                                 SOCK_CLOEXEC + SOCK_NONBLOCK);
      -- Only MacOS does not support adding flags to the sock_type argument of
      -- create_socket.
      
      -- Note the addition of the flags. These  would be "ored" in the c
      -- world. We could do something like that if we really tried, but
      -- we know that this is a flag, and thus must be a single bit that
      -- does not conflict with the type value, and hence simple addition
      -- here acheives the same result.
      
   begin
      -- For UDP sockets only, we will pre-allocate descriptors for both IPv4
      -- IPv6. This is because UDP is connectionless and we need to be prepared
      -- to send/receive messages to/from any address (v4 or v6).
      --
      -- For TCP, we need to know what address we are connecting to before we
      -- can decide which socket to allocate, and it only makes sense to have
      -- a single socket active at any given time.
      
      case Socket.Protocol is
         when TCP =>
            null;
            
         when UDP =>
            -- See socket(2) manpage.
            -- socket returns an invalid descriptor if the allocation fails.
            --
            -- If allocation fails here, we just leave it since raising an
            -- exception at this point is less likely to be handled sanely.
            --
            -- It will be less surprising for the user to get an exception
            -- when they actually try to use the socket
            
            Socket.UDP_v4_Socket := create_socket 
              (domain    => PF_INET,
               sock_type => SOCK_DGRAM + Flags);
            
            Socket.UDP_v6_Socket := create_socket
              (domain    => PF_INET6,
               sock_type => SOCK_DGRAM + Flags);
            
            if AURA.Platform_Flavor = "darwin" then
               -- MacOS does not support flags for create_socket. This means
               -- no CLOEXEC, which we have to shrug to. For non-blocking,
               -- we do that directly
               declare
                  Discard: int;
               begin
                  Discard := set_nonblocking ( Socket.UDP_v4_Socket );
                  Discard := set_nonblocking ( Socket.UDP_v6_Socket );
               end;
            end if;
            
      end case;

   end Initialize;
   
   --------------
   -- Finalize --
   --------------
   
   procedure Finalize (Socket: in out UNIX_Socket) is

      -- Probably don't need three seperate return variables here
      Discard: int;
   begin
      -- Close the socket file descriptor (use the close system call (close(2))
      
      -- The sockets are always closed on finalization. In the case of UDP,
      -- the sockets should only be closed when we know we're not going to
      -- need them anymore (now). For TCP, connections should be properly
      -- closed by a call to "shutdown", but not close - so that data can
      -- still be optionally sent/received.
      
      case Socket.Protocol is

         when TCP =>
            -- Only make the syscall if there is actually a descriptor to close
            
            if Socket.TCP_Socket /= Invalid_Descriptor then
               Discard := close(fd => Socket.TCP_Socket);
            end if;

         when UDP =>
         
            if Socket.UDP_v4_Socket /= Invalid_Descriptor then
               Discard := close(fd => Socket.UDP_v4_Socket);
            end if;

            if Socket.UDP_v6_Socket /= Invalid_Descriptor then
               Discard := close(fd => Socket.UDP_v6_Socket);
            end if;

      end case;

   end Finalize;
   
   
   -----------------
   -- TCP_Connect --
   -----------------
   
   procedure TCP_Connect (Socket : in out UNIX_Socket;
                          Address: in     IP.IP_Address;
                          Port   : in     INET.TCP.TCP_Port;
                          Status :    out Operation_Status;
                          Errno  :    out Interfaces.C.int)
   is
      use INET.IP;
      
      -- connect via an intermediary 
      function connect (s   : in int; 
                        addr: in IPv4_Address;
                        port: in in_port_t)
                       return int with
        Convention => C, Import => True,
        External_Name => "__inet_internal_unix_sockets_sys_do_connect4";
      
      function connect (s   : in int; 
                        addr: in IPv6_Address;
                        port: in in_port_t)
                       return int with
        Convention => C, Import => True,
        External_Name => "__inet_internal_unix_sockets_sys_do_connect6";
      
      -- Remember that private types are passed according to the full view,
      -- which means name is a passed as an array (therefore a pointer) to
      -- the first element - which is what is expected
      

          
      Retval, Discard: int;
      Option_Enable: aliased int := 1;
   begin
      Errno := 0;
      
      -- Attempt to open a connection, and return the status.
      
      -- We first check if the socket they wish to use is initialized, since
      -- that is an error. 
      
      -- Close the socket if it is currently allocated. Note the discriminent
      -- check on the call to close which is protected by the Precondition.
      
      if Socket_Active (Socket) then
         Discard := close (Socket.TCP_Socket);
         Socket.TCP_Socket := Invalid_Descriptor;
      end if;
      
      -- Open the new socket.
      
      Socket.TCP_Socket := create_socket
        (domain    => (case Address.Version is 
                          when IPv4 => PF_INET,
                          when IPv6 => PF_INET6),
         sock_type => SOCK_STREAM + SOCK_CLOEXEC);
      
      -- Note the addition of the flags. These  would be "ored" in the c
      -- world. We could do something like that if we really tried, but
      -- we know that this is a flag, and thus must be a single bit that
      -- does not conflict with the type value, and hence simple addition
      -- here acheives the same result.
      
      -- Note that we don't set NONBLOCK for the socket until after the
      -- connection is established. Dealing with connection attempts over
      -- a nonblocking socket is too poorly defined and unreliable.
      
      if Socket.TCP_Socket = Invalid_Descriptor then
         Errno_Status (Errno, Status);
         return;
      end if;

      -- Good socket.
      -- Now the connection attempt
      
      case Address.Version is
         when IPv4 =>
            Retval := connect (s    => Socket.TCP_Socket,
                               addr => Address.v4_Address,
                               port => in_port_t (Port));
            
         when IPv6 =>
            Retval := connect (s    => Socket.TCP_Socket,
                               addr => Address.v6_Address,
                               port => in_port_t (Port));
      end case;
      
      if Retval = 0 then
         -- Success
         -- Now set the socket to non-blocking
         Retval := set_nonblocking (Socket.TCP_Socket);
         
         if Retval = -1 then
            -- This really should not happen
            Errno_Status (Errno, Status);
            raise Program_Error with "INET.UNIX_Sockets.TCP_Connect: "
              & "Could not set new socket to non-blocking. "
              & "errno =" & int'Image (Errno);
         else
            Status := OK;
         end if;
         
      else
         Discard := close (Socket.TCP_Socket);
         Socket.TCP_Socket := Invalid_Descriptor;
         Errno_Status (Errno, Status);
      end if;
      
   exception
      when others =>
         if Socket.TCP_Socket /= Invalid_Descriptor then
            Discard := close (Socket.TCP_Socket);
            Socket.TCP_Socket := Invalid_Descriptor;
         end if;
         
         raise;
   end TCP_Connect;
   
   -----------------------
   -- TCP_Bind_Listener --
   -----------------------
   
   procedure TCP_Bind_Listener (Socket : in out UNIX_Socket;
                                Address: in     IP.IP_Address;
                                Port   : in     INET.TCP.TCP_Port;
                                Backlog: in     Positive;
                                Status :    out Operation_Status;
                                Errno  :    out Interfaces.C.int)
   is
      use INET.IP;
      
      function bind (s   : int;
                     addr: IPv4_Address;
                     port: in_port_t)
                    return int with
        Convention => C, Import => True,
        External_Name => "__inet_internal_unix_sockets_sys_do_bind4";
      
      function bind (s   : int;
                     addr: IPv6_Address;
                     port: in_port_t)
                    return int with
        Convention => C, Import => True,
        External_Name => "__inet_internal_unix_sockets_sys_do_bind6";
      
      function listen (s: int; backlog: int) return int with
        Convention => C, Import => True,
        External_Name => "listen";
      -- listen(2) - libc
      
      Retval, Discard: int;
   begin
      Errno := 0;
      
      if Socket_Active (Socket) then
         raise Program_Error with "Bind attempted on bound socket";
      end if;
      
      -- Open the new socket, with the address family determined by the version
      -- of the Address parameter
      
      Socket.TCP_Socket := create_socket
        (domain    => (case Address.Version is 
                          when IPv4 => PF_INET,
                          when IPv6 => PF_INET6),
         sock_type => SOCK_STREAM + SOCK_CLOEXEC);
      
      if Socket.TCP_Socket = Invalid_Descriptor then
         Errno_Status (Errno, Status);
         return;
      end if;
      
      
      case Address.Version is
         when IPv4 =>
            Retval := bind (s    => Socket.TCP_Socket,
                            addr => Address.v4_Address,
                            port => in_port_t (Port));
            
         when IPv6 =>
            Retval := bind (s    => Socket.TCP_Socket,
                            addr => Address.v6_Address,
                            port => in_port_t (Port));
      end case;
      
      if Retval /= 0 then
         Errno_Status (Errno, Status);
         Discard := close (Socket.TCP_Socket);
         Socket.TCP_Socket := Invalid_Descriptor;
         return;
      end if;
      
      Retval := listen (s       => Socket.TCP_Socket,
                        backlog => int (Backlog));
      
      if Retval = 0 then
         -- Success
         Status := OK;
      else
         Errno_Status (Errno, Status);
         Discard := close (Socket.TCP_Socket);
         Socket.TCP_Socket := Invalid_Descriptor;
      end if;
      
   exception
      when others =>
         if Socket.TCP_Socket /= Invalid_Descriptor then
            Discard := close (Socket.TCP_Socket);
            Socket.TCP_Socket := Invalid_Descriptor;
         end if;
         
         raise;
   end TCP_Bind_Listener;
   
   ---------------------------
   -- TCP_Accept_Connection --
   ---------------------------
   
   procedure TCP_Accept_Connection (Listen_Socket : in     UNIX_Socket;
                                    New_Socket    : in out UNIX_Socket;
                                    Client_Address:    out IP.IP_Address;
                                    Client_Port   :    out INET.TCP.TCP_Port;
                                    Status        :    out Operation_Status;
                                    Errno         :    out Interfaces.C.int)
   is
      use INET.IP;
      
      procedure tcp_accept (ls   : in     int;
                            cs   :    out int;
                            port :    out in_port_t;
                            addr4:    out IPv4_Address;
                            addr6:    out IPv6_Address;
                            ipver:    out int)
      with
        Convention => C, Import => True,
        External_Name => "__inet_internal_unix_sockets_sys_do_accept";
      -- ipver is set to 4 or 6 depending on the family of the address of the
      -- actual client. Also sets the new socket to be nonblocking
      
      -- We are going to actually allow the possibility that the accept
      -- operation could give us a connection from either IPv4 or IPv6.
      -- This is (at the time unlikely), but it does follow the general
      -- structure of the higher-level packages.
      
      Client_v4: IPv4_Address;
      Client_v6: IPv6_Address;
      port_tmp : in_port_t;
      ipver    : int := -1;
      Discard  : int;
      Retval   : int;
      
   begin
      if not Socket_Active (Listen_Socket) then
         raise Program_Error with "Listener socket not bound.";
      end if;
      
      if Socket_Active (New_Socket) then
         Discard := close (New_Socket.TCP_Socket);
         New_Socket.TCP_Socket := Invalid_Descriptor;
      end if;
      
      tcp_accept (ls    => Listen_Socket.TCP_Socket,
                  cs    => New_Socket.TCP_Socket,
                  port  => port_tmp,
                  addr4 => Client_v4,
                  addr6 => Client_v6,
                  ipver => ipver);
      
      if New_Socket.TCP_Socket = Invalid_Descriptor then
         Client_Port := 0;
         Client_Address := IPv6_Wildcard;
         -- Set these to avoid the possibility of a constraint error on
         -- uninitialized inputs.
         
         Errno_Status (Errno, Status);
         return;
      end if;
      
      Retval := set_nonblocking (New_Socket.TCP_Socket);
      
      if Retval = -1 then
         -- This really should not happen
         Errno_Status (Errno, Status);
         raise Program_Error with "INET.UNIX_Sockets.TCP_Accept_Connection: "
           & "Could not set new socket to non-blocking. "
           & "errno =" & int'Image (Errno);
      end if;
      
      
      case ipver is
         when 4 =>
            Client_Address := IP_Address'(Version    => IPv4,
                                          v4_Address => Client_v4);
         when 6 =>
            Client_Address := IP_Address'(Version    => IPv6,
                                          v6_Address => Client_v6);
            
         when others =>
            -- There was some error getting the address back. We'll assume the
            -- worst. Honestly this is likely a program error of some kind,
            -- since this really won't happen by action of a user or an actual
            -- client. It likely indicates a portability issue
            
            -- It is a serrious enough problem that an assertion is really not
            -- enough. We cannot allow these through under any circumstances,
            -- as it could present a serrious security vulnerability.
            
            raise Program_Error with
              "Unable to obtain client address on accept";
      end case;
      
      Client_Port := INET.TCP.TCP_Port (port_tmp);
      Status := OK;
      
   exception
      when others =>
         if New_Socket.TCP_Socket /= Invalid_Descriptor then
            Discard := close (New_Socket.TCP_Socket);
            New_Socket.TCP_Socket := Invalid_Descriptor;
         end if;
         
         raise;
      
   end TCP_Accept_Connection;
   
   ------------------
   -- TCP_Shutdown --
   ------------------
   
   procedure TCP_Shutdown (Socket   : in out UNIX_Socket;
                           Direction: in     Data_Direction)
   is
      
      function shutdown (s: in int; how: in int) return int with 
        Convention => C, Import => True,
        External_Name => "shutdown";
      -- shutdown(2)
      
      How, Discard: int;
   begin
      
      if Socket.Protocol /= TCP then
         raise Program_Error with
           "TCP_Shutdown can only be used with TCP sockets!";
      elsif not Socket_Active (Socket) then
         return;
      end if;
      
      case Direction is
         when Outbound => How := SHUT_WR;
         when Inbound  => How := SHUT_RD;
         when Both     => How := SHUT_RDWR;
      end case;
      
      Discard := shutdown (s => Socket.TCP_Socket, how => How);
      
      -- We don't care if this fails, since if it did, there is not much that
      -- can realistically be done about it, and any side-effects to further
      -- reads or writes would cause an exception during those operations, 
      -- which is more readily handled.
      
   exception
      when others => null;
   end TCP_Shutdown;
   
   ---------------------------
   -- TCP_Receive_Immediate --
   ---------------------------
   
   procedure TCP_Receive_Immediate (Socket   : in out UNIX_Socket;
                                    Buffer   :    out Stream_Element_Array;
                                    Last     :    out Stream_Element_Offset;
                                    Status   :    out Operation_Status;
                                    Errno    :    out Interfaces.C.int)
   is
      -- recv(2) - libc
      function recv 
        (s  : in int;    buf  : out Stream_Element_Array;
         len: in size_t; flags: in int)
                    return ssize_t
      with
        Import        => True,
        Convention    => C,
        External_Name => "recv";
      
      Retval: ssize_t;
      Flags: int := 0;
      Sizeof_Stream_Element: constant := Stream_Element'Size / 8;

   begin
      if not Socket_Active (Socket) then
         raise Program_Error with "Socket not allocated (connected).";
      end if;
      
      Errno := 0;
      
      -- Don't do anything on an empty buffer
      if Buffer'Length = 0 then
         Last := Buffer'Last;
         Status := OK;
         return;
      end if;
      
      Retval := recv (s     => Socket.TCP_Socket,
                      buf   => Buffer,
                      len   => Buffer'Length * Sizeof_Stream_Element,
                      flags => 0);
      
      if Retval < 0 then
         Last := Buffer'First - 1;
         Errno_Status (Errno, Status);
      else
         Last := Buffer'First 
           + Stream_Element_Offset (Retval / Sizeof_Stream_Element)
           - 1;
         
         Status := OK;
      end if;
      
   end TCP_Receive_Immediate;
   
   ------------------------
   -- TCP_Send_Immediate --
   ------------------------
   
   procedure TCP_Send_Immediate (Socket   : in out UNIX_Socket;
                                 Buffer   : in     Stream_Element_Array;
                                 Last     :    out Stream_Element_Offset;
                                 Status   :    out Operation_Status;
                                 Errno    :    out Interfaces.C.int)
   is
      function send (s: int; msg: Stream_Element_Array; len: size_t; flags: int)
                    return ssize_t
      with
        Import        => True,
        Convention    => C,
        External_Name => "send";
      
      Retval: ssize_t;
      Sizeof_Stream_Element: constant := Stream_Element'Size / 8;
      
   begin
      if not Socket_Active (Socket) then
         raise Program_Error with "Socket not allocated (connected).";
      end if;
      
      Errno := 0;
      
      -- Don't bother sending nothing
      if Buffer'Length = 0 then
         Last := Buffer'Last;
         Status := OK;
         return;
      end if;
      
      Retval := send (s     => Socket.TCP_Socket,
                      msg   => Buffer,
                      len   => Buffer'Length * Sizeof_Stream_Element,
                      flags => MSG_NOSIGNAL);
      
      if Retval < 0 then
         Last := Buffer'First - 1;
         Errno_Status (Errno, Status);
      else
         Last := Buffer'First
           + Stream_Element_Offset (Retval / Sizeof_Stream_Element)
           - 1;
         Status := OK;
      end if;
      
   end TCP_Send_Immediate;
   
   ----------
   -- Wait --
   ----------
   
   procedure Wait_Actual (Socket      : in UNIX_Socket;
                          Direction   : in Data_Direction;
                          Wait_Forever: in Boolean;
                          Timeout     : in Duration)
   is
      type fd_set is array (1 .. 2) of int;
      
      function do_poll (fds   : fd_set; fd_count: int; events: short;
                        no_timeout: int; timeout: timespec)
                       return int
      with
        Import        => True,
        Convention    => C,
        External_Name => "__inet_internal_unix_sockets_sys_do_poll";
      -- Invokes (p)poll(2) for fd, and the supplied events.
      --
      -- We dont invoke (p)poll directly because of the nfds_t type being
      -- very unportable.
      --
      -- do_poll returns the value returned from (p)poll(2)
      
      fds       : fd_set := (others => -1);
      events    : short;
      fd_count  : int := 0;
      Timeout_TS: timespec := To_Timespec (Timeout);
      
      Retval: int;
      Status: Operation_Status;
      Errno : int;
   begin
      case Socket.Protocol is
         when TCP =>
            fds(1) := Socket.TCP_Socket;
            fd_count := 1;
            
         when UDP =>
            fds(1) := Socket.UDP_v4_Socket;
            fds(2) := Socket.UDP_V6_Socket;
            fd_count := 2;
      end case;
      
      case Direction is
         when Outbound => events := POLLOUT;
         when Inbound  => events := POLLIN;
         when Both     => events := POLLOUT + POLLIN;
      end case;
      
      Retval := do_poll (fds        => fds,
                         fd_count   => fd_count,
                         events     => events,
                         no_timeout => (case Wait_Forever is
                                           when True => 1, when False => 0),
                         timeout    => Timeout_TS);
      
      if Retval < 0 then
         Errno_Status (Errno, Status);
         
         if Status = Other_Failure then
            -- According to the man page for poll(2), there are only three
            -- possible errnos: EFAULT, EINTR, and EINVAL. Out of those three
            -- the second means a signal tripped the poll. The others mean
            -- either the fd was wrong (unlikely) or the timespec was out
            -- of range (possible). Either way, this is a classic case for
            -- an exception
            
            raise Constraint_Error with "INET.UNIX_Sockets.Wait: "
              & "Timeout value out of range or bad socket. "
              & "errno =" & int'Image (Errno);
            
         end if;
      end if;
      
      -- Otherwise, we don't report anything about an interrupted or timed-
      -- out poll back because:
      --
      -- A. If there was an interruption (a signal, for example), then the
      --    following send/recv will return EAGAIN, the actual elapsed time
      --    will be checked, and if there is still time remaining for the
      --    higher-level operation, do_poll will be invoked again
      --
      -- B. If there is an error on the socket then the following send/recv
      --    will indicate the specific error.
      --
      -- C. If the poll timed-out, the subsequent send/recv will fail with
      --    a status of Not_Ready, which the higher-level operation will
      --    recognise as being a time-out or interruption, and will check
      --    the total time remaining. If time still remains, do_poll will
      --    be invoked again.
      
   end Wait_Actual;
   
   ----------------------------------------------------------------------
   
   procedure Wait (Socket   : in UNIX_Socket;
                   Direction: in Data_Direction)
   is begin
      Wait_Actual (Socket       => Socket,
                   Direction    => Direction,
                   Wait_Forever => True,
                   Timeout      => 0.0);
   end Wait;
   
   ----------------------------------------------------------------------
   
   procedure Wait (Socket   : in UNIX_Socket;
                   Direction: in Data_Direction;
                   Timeout  : in Duration)
   is begin
      Wait_Actual (Socket       => Socket,
                   Direction    => Direction,
                   Wait_Forever => False,
                   Timeout      => Timeout);
   end Wait;
   
   ---------------------------
   -- TCP_Socket_Descriptor --
   ---------------------------
   
   function TCP_Socket_Descriptor (Socket: UNIX_Socket) return int is
     (Socket.TCP_Socket);
   
   ----------------------------
   -- UDP_Socket_Descriptors --
   ----------------------------
   
   procedure UDP_Socket_Descriptors (Socket         : in     UNIX_Socket;
                                     IPv4_Descriptor:    out int;
                                     IPv6_Descriptor:    out int)
   is begin
      IPv4_Descriptor := Socket.UDP_v4_Socket;
      IPv6_Descriptor := Socket.UDP_v6_Socket;
   end UDP_Socket_Descriptors;
   
begin
   block_sigpipe;
   
   -- Ensure that SIGPIPE cannot be delivered at all to the process.
   -- It is totally useless to the Ada implementation, and GNAT doesn't
   -- do anything with it normally, so it causes immediate termination.
   -- This is not a good thing for a server!
   
   -- Why not use Ada interrupts? Portability.
   
   -- Speaking of portability.. We'd actually like to set SO_NOSIGPIPE on
   -- all new socket creations (which will always be done through this package,
   -- even for TLS), but lo Linux can't do that. BSD, MacOS, Solaris = no prob.
   -- Linux somehow doesn't have this option.
   
end INET.Internal.UNIX_Sockets;
