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

-- This package provides the common TLS abstractions that are shared amongst
-- both reliable-stream oriented TLS and unreliable datagram oriented DTLS.
--
-- Note that DTLS support is not yet implemented, but is expected in the
-- future.
--
-- This package's TLS implementation is a binding to LibreSSL's libtls

with Ada.Streams;

private with Ada.Finalization;
private with Ada.Strings.Unbounded;
private with Interfaces.C;
private with Interfaces.C.Strings;
private with Interfaces.C.Pointers;
private with INET.Internal.TLS;

package INET.TLS is
   
   TLS_Error: exception;
   
   -- Raised when libtls indicates an error. The message will contain the
   -- error message reported by libtls.
   
   TLS_Handshake_Failed: exception;
   
   -- Raised explicitly in the case where a handshake fails. The message will
   -- contaion the error message reported by libtls.
   
   -----------------------
   -- TLS_Security_Data --
   -----------------------
   
   type TLS_Security_Data(<>) is tagged limited private;
   
   -- TLS_Security_Data is used to either contain any number of TLS security
   -- objects, that are typically stores in files. These include:
   -- - Public certificates
   -- - Private keys
   -- - Root certificate chains
   -- - OCSP staples
   
   function Load_File (Path: String) return TLS_Security_Data;
   function Load_File (Path: String; Password: String) 
                      return TLS_Security_Data;
   
   -- Loads the content of the file at Path into memory. This implies heap
   -- allocation. The allocation is always explicitly zeroed and then
   -- freed at finalization.
   
   function Associate_File (Path: String) return TLS_Security_Data;
   
   -- Associates the file (including directories) at Path with the
   -- TLS_Security_Data. The file is not loaded into memory.
   --
   -- See TLS_Configuration.Root_Certificates for information on including
   -- pointing to directories.
   
   procedure Output
     (Stream: not null access Ada.Streams.Root_Stream_Type'Class;
      Data  : in TLS_Security_Data);
   
   for TLS_Security_Data'Output use Output;
   
   -- If the Data was either obtained through Load_File or
   -- TLS_Security_Data'Input of another TLS_Security_Data object that was
   -- itself obtained through Load_File, this- operation streams the actual
   -- data stored in memory, effectively copying it.
   --
   -- If Data was obtained through Associate_File, this operation simply
   -- streams the path of the associated file, but does not transfer actual
   -- data.
   --
   -- These streaming facilities (TLS_Security_Data'Output), allows for the
   -- transfer of TLS_Security_Objects from a parent process to a (less
   -- privledged) child process which likely could not read the actual file
   -- itself, as is common when implementing security best-practices

   
   function Input (Stream: not null access Ada.Streams.Root_Stream_Type'Class)
                  return TLS_Security_Data;
   
   for TLS_Security_Data'Input use Input;
   
   -- The other side of Output - see above.

   System_CA_Chain: constant TLS_Security_Data;
   
   -- A file-type System_CA_Chain that can be used as the formal to the 
   -- Root_CA_Certs parameter of TLS_Configuration.Root_Certificates.
   --
   -- This value is set by a query to libtls during elaboration of this
   -- package. If libtls does not know where to find the CA root, that
   -- call will likely raise TLS_Error with a message from libtls
   
   --------------------
   -- TLS_Session_ID --
   --------------------
   
   type TLS_Session_ID is private;
   
   -- The TLS_Session_ID type stores a session id. The type may be streamed to
   -- share it among multiple partitions. Alternatively, a value may be set by
   -- initializing it with a (true) random value.
   --
   -- Any use of TLS_Session_ID by other subprograms in this package (and its
   -- children) raises a Program_Error.
   
   function Valid (ID: TLS_Session_ID) return Boolean;
   
   procedure Randomize_ID (ID: out TLS_Session_ID) with
     Post => Valid (ID);
   
   --------------------
   -- TLS_Ticket_Key --
   --------------------
   
   type TLS_Ticket_Key is private;
   
   -- The TLS_Ticket_Key type stores a ticket key. The type may be streamed to
   -- share it among multiple partitions. Alternatively, a new key may be
   -- generated from a crayptographically random source.
   --
   -- Any use of an unititialized TLS_Ticket_Key by other subprograms in this
   -- package (and its children) raises a Program_Error.
   
   function Valid (Key: TLS_Ticket_Key) return Boolean;
   
   -- Returns True iff the key has been initialized.
   
   procedure Randomize_Key (Key: out TLS_Ticket_Key) with
     Post => Valid (Key);
   
   -- Generates a random key from a high entropy source. Also generates a
   -- random "revision" value from the same source.
   
   procedure Zero_Key (Key: out TLS_Ticket_Key) with
     Post => not Valid (Key);
   
   -- Explicitly zeroes and invalidates a key. Can be used before deallocation.
   
   -----------------------
   -- TLS_Configuration --
   -----------------------
   
   TLS_Configuration_Error: exception;
   
   -- Returned by most of the TLS_Configuration operations if the operation
   -- failed at the libtls level. The libtls error message becomes the
   -- TLS_Configuration_Error's message.
   
   type TLS_Configuration is abstract tagged limited private;
   
   -- TLS_Configuration'Class objects contains a set of configuration values
   -- that determine the parameters of a TLS connection.
   --
   -- TLS_Server_Configuration objects may be reused among any number of
   -- TLS_Connection objects. Libressl's libtls ensures that the underlying
   -- structure is task-safe, and so is TLS_Configuration.
   --
   -- The TLS_Configuration must have a lifetime that is the same as or
   -- longer than TLS_Connection objects that use it.
   --
   -- Note, however, that any TLS_Security_Data objects have their data
   -- copied into the TLS_Configuration object, and need not have the
   -- same lifetime as the TLS_Configuration object itself.
   --
   -- For security purposes, the TLS_Configuration object may have all
   -- secret data cleared. Doing so will prevent any further Server-side
   -- connections being established, unless the secrets are re-loaded.
   --
   -- This may be useful for single-client server processes that are forked
   -- per connection, where maximum security is desired.
   
   type TLS_Protocol_Selection is
      record
         TLS_v1_0: Boolean := False;
         TLS_v1_1: Boolean := False;
         TLS_v1_2: Boolean := True;
         TLS_v1_3: Boolean := True;
      end record;
   
   -- Represents the selected (accepted) protocols for a configuration. The
   -- deaults as indicated will be the default for all TLS_Configurations
   -- without explicit configuration. This set of defaults is derrived from
   -- libressl's libtls defaults as described in tls_config_set_protocols(3)
   
   procedure Acceptable_Protocols
     (Configuration: in out TLS_Configuration;
      Protocols    : in     TLS_Protocol_Selection);
   
   -- Sets the acceptable protocols for Configuration
   
   procedure Root_Certificates (Configuration: in out TLS_Configuration;
                                Root_CA_Certs: in     TLS_Security_Data'Class);
   
   -- Sets a specific set of root certificates for verification of the remote
   -- peer's certificate. If Root_CA_Certs is Associated with a file which is
   -- actually a directory, the contents of the directory will be scanned for
   -- root certificates.

   
   procedure Key_Pair (Configuration: in out TLS_Configuration;
                       Certificate  : in     TLS_Security_Data'Class;
                       Key          : in     TLS_Security_Data'Class);
   
   -- Sets the public certificate and private key pair for the active
   -- authenication of a session. This is usually needed for servers, but may
   -- also be used when client authentication is requred.
   --
   -- Note that this operation copies the data from Certificate and Key into
   -- the Configuration's own internal storage.
   
   procedure Clear_Keys (Configuration: in out TLS_Configuration);
   
   -- Removes and zeros any Key_Pair that has been stored in Configuration.
   -- After invoking Clear_Keys, any further connections created with
   -- Configuration will not be capable of authenticating themselves.
   
   procedure Certificate_Revocation_List 
     (Configuration  : in out TLS_Configuration;
      Revocation_List: in     TLS_Security_Data'Class);
   
   -- Sets the Certificate Revocation List to be used to reject public
   -- certificates that have been revoked.
   
   procedure OCSP_Staple (Configuration: in out TLS_Configuration;
                          Staple       : in     TLS_Security_Data'Class);
   
   -- Sets the OCSP_Staple from a DER encoded file typically generated by
   -- libressl's ocspcheck(8) utility, in conjuction with the local peer's
   -- certificate and their CA.
   --
   -- The OCSP staple is sent with the local peer's certificate (typically
   -- a server), and allows the remote peer to validate the certificate
   -- without needing to contact the CA or rely on a revoation list.
   
   procedure Require_OCSP_Staple (Configuration: in out TLS_Configuration);
   
   -- Sets the configuration to require the remote peer always provide a
   -- OCSP staple during the handshake.
   
   procedure Supported_ALPNs (Configuration: in out TLS_Configuration;
                              ALPN_List    : in     String);
   
   -- Sets the ALPN protocols to be supported by the configuration.
   -- ALPN_List shall be a "comma separated list of protocols, in order of
   -- preference"
   
   -- Implementation Facilities --
   -------------------------------
   
   procedure Get_External_Handle (Configuration: in     TLS_Configuration;
                                  Handle       :    out INET_Extension_Handle);
   
   -- Useable only by the TLS implementation. This is used by the internal
   -- subprograms which need to pass libtls' internal handle of a configuration
   -- object as a parameter to the libtls library call.
   --
   -- Note that this does not violate Ada privacy, since the handle is
   -- an external analog to a TLS_Configuration'Class object, which is
   -- visible. Obviously that actual handle needs to be a component of the
   -- TLS_Configuration object, but we don't want to expose all parts of the
   -- object, and so this acheives a similar end. It could be anagolous to
   -- associating a private type with an ID of some kind, which can be
   -- obtained through a similar primitive operation.
   --
   -- The one "con" is that we lose some type safty with this approach,
   -- but with the use being so limited to internal implementation details,
   -- this presents a limited danger.
   --
   -- That being said, the INET package has been designed such that a
   -- client of INET cannot ever obtain a handle anyways, and even if they
   -- did, they wouldn't have any use for it.
   --
   -- If Handle is "null", Program_Error is raised.
   
   ------------------------------
   -- TLS_Client_Configuration --
   ------------------------------
   
   type TLS_Client_Configuration is limited new TLS_Configuration with private;
   
   -- Using a TLS_Client_Configuration with TLS_Connection.Connect/Upgrade
   -- /Secure will cause the TLS session to be negotiated as if the local
   -- peer is the client.
   
   procedure Session_Storage
     (Configuration: in out TLS_Client_Configuration;
      Path         : in     String);
   
   -- Attaches a regular file at Path to the configuration for the storage of
   -- session data, such as tickets. This allows more efficient reconnection
   -- with servers within a session lifetime
   --
   -- The file at path must be read-write accessible by only the user under
   -- which the partition is executing.
   --
   -- If Session_Storage has already been invoked for Configuration,
   -- Program_Error is raised.
   
   
   ------------------------------
   -- TLS_Server_Configuration --
   ------------------------------
   
   type TLS_Server_Configuration is limited new TLS_Configuration with private;
   
   -- Using a TLS_Server_Configuration with TLS_Connection.Connect/Upgrade
   -- /Secure will cause the TLS session to be negotiated as if the local
   -- peer is the server.
   
   procedure Session_Lifetime (Configuration: in out TLS_Server_Configuration;
                               Lifetime     : in     Duration);
   
   -- Sets the session lifetime for session tickets. TLS_Server_Configuration
   -- objectes are initialized with a lifetime of 0.0. A lifetime of 0.0
   -- disables session tickets. Therefore, by default, TLS_Server_Configuration
   -- objects will have session tickets disabled. Set this value to enable them
   --
   -- For refence, the OpenBSD httpd server uses a 2 hour lifetime (as of
   -- OpenBSD 6.7).
   --
   -- Note that Duration is rounded to the nearest second.
   
   procedure Session_ID (Configuration: in out TLS_Server_Configuration;
                         ID           : in     TLS_Session_ID)
   with Pre'Class => Valid (ID);
   
   -- If Session_ID is not Valid, Program_Error is raised
   
   procedure Add_Ticket_Key (Configuration: in out TLS_Server_Configuration;
                             Key          : in     TLS_Ticket_Key)
   with Pre'Class => Valid (Key);
   
   -- Each TLS_Server_Configuration contains some arbitrary list of ticket
   -- keys, which are rotated once per session lifetime. Add_Ticket_Key
   -- adds a key to this queue. If Add_Ticket_Key is not invoked, the
   -- TLS_Server_Configuration object will automatically generate random keys.
   --
   -- The purpose of Add_Ticket_Key is to synchronize ticket keys amongst
   -- muiltiple TLS_Server_Configuration objects - typically in seperate
   -- processes. It is important to synchronize keys on period shorter than
   -- the session lifetime. The libressl documentation is sparse when it comes
   -- to explaining how this works, but the OpenBSD httpd server rekeys on
   -- a period that is 1/4 that of the session lifetime.
   --
   -- If Key is not Valid, Program_Error is raised.
   
   procedure Verify_Client (Configuration: in out TLS_Server_Configuration);
   
   -- Requires the client to send a certificate to the server for verification
   
private
   
   -----------------------
   -- TLS_Security_Data --
   -----------------------
   
   use type Interfaces.Unsigned_8;
   use type Interfaces.C.size_t;
   
   package UBS renames Ada.Strings.Unbounded;
   
   subtype Security_Data_Element is Interfaces.Unsigned_8;
   
   type Raw_Security_Data is 
     array (Interfaces.C.size_t range <>) of aliased Security_Data_Element
   with Pack;
   
   type Security_Data_Allocation is access Raw_Security_Data;
   
   package Security_Data_Pointers is new Interfaces.C.Pointers
     (Index              => Interfaces.C.size_t,
      Element            => Security_Data_Element,
      Element_Array      => Raw_Security_Data,
      Default_Terminator => 0);  -- Not used
   
   -- <tls.h> libtls defines all such data as uint8_t pointers
   
   type Security_Data_Format is (File, Memory);
   
   type TLS_Security_Data (Format: Security_Data_Format) is 
     limited new Ada.Finalization.Limited_Controlled with
      record
         case Format is
            when File =>
               Path: UBS.Unbounded_String;
               
            when Memory =>
               Data          : Security_Data_Pointers.Pointer := null;
               Length        : Interfaces.C.size_t            := 0;
               
               Ada_Allocation: Security_Data_Allocation       := null;
            
               -- If non-null, must be deallocated via Unchecked_Deallocation.
               -- Data points to the element at Ada_Allocation'First.
               --
               -- If null, Data points at a C-style equivalent to
               -- Raw_Security_Data (first element), and must be deallocated
               -- through libtls' unload_file(3)
         end case;
      end record;
   
   -- Unlike with the the likes of TLS_Configuration and TLS_Context, we cannot
   -- simply store a handle to some transparent type, since we want the ability
   -- to stream these data. Therefore we need more awareness of the data itself,
   -- and who exactly allocated it.
   
   overriding
   procedure Finalize (Data: in out TLS_Security_Data);
   
   -- If Data is of Format = Memory, the associated Data is explicitly zeroed
   -- if Dont_Zero is False, and is then deallocated
   
   function tls_default_ca_cert_file return Interfaces.C.Strings.chars_ptr with
     Import => True, Convention => C,
     External_Name => "tls_default_ca_cert_file";
   
   System_CA_Chain: constant TLS_Security_Data
     := (Ada.Finalization.Limited_Controlled with
         Format => File, 
         Path => UBS.To_Unbounded_String
           (Interfaces.C.Strings.Value (tls_default_ca_cert_file)));
   
   --------------------
   -- TLS_Session_ID --
   --------------------
   
   -- TLS_Session_ID is an array of "unsigned chars". LibreSSL's tls.h defines
   -- a "maximum size", as a macro. We will simply hard-code that value here.
   -- This is safe and harmless since all of the libtls operations that accept
   -- a session id also take a length parameter.
   --
   -- To detect changes during testing, additional Assert pragmas exist in the
   -- body to explicitly check against the value of the macro.
   
   
   TLS_MAX_SESSION_ID_LENGTH: constant := 32;
   -- <tls.h>
   
   subtype Session_ID_Data is
     INET.Internal.TLS.Random_Data (1 .. TLS_MAX_SESSION_ID_LENGTH);
   
   type TLS_Session_ID is
      record
         ID         : Session_ID_Data;
         Initialized: Boolean := False;
      end record;
   
   --------------------
   -- TLS_Ticket_Key --
   --------------------
   
   -- Similarly as per TLS_Session_ID above
   
   TLS_TICKET_KEY_SIZE: constant := 48;
   
   use type Interfaces.Unsigned_32;
   subtype Key_Revision is Interfaces.Unsigned_32;
   -- <tls.h>
   
   subtype Ticket_Key_Data is
     INET.Internal.TLS.Random_Data (1 .. TLS_MAX_SESSION_ID_LENGTH);
   
   type TLS_Ticket_Key is
      record
         Key        : Ticket_Key_Data;
         Revision   : Key_Revision;
         Initialized: Boolean := False;
      end record;
   
   -----------------------
   -- TLS_Configuration --
   -----------------------
   
   -- TLS_Configuration holds a (C) pointer to the "struct tls_config"
   -- configuration structure that is managed by libtls
   -- (the "extension"/"external" handle). TLS_Configuration automatically 
   -- initializes a new configuration, and automatically invokes
   -- tls_config_free at finalization
   
   type Configuration_Handle is new INET_Extension_Handle;
   
   Null_Configuration_Handle: constant Configuration_Handle 
     := Configuration_Handle (Null_Handle);
   
   type TLS_Configuration is limited
     new Ada.Finalization.Limited_Controlled with
      record
         Handle: Configuration_Handle := Null_Configuration_Handle;
      end record;
   
   overriding
   procedure Initialize (Configuration: in out TLS_Configuration);
   
   -- Allocates a new default configuration
   
   overriding
   procedure Finalize (Configuration: in out TLS_Configuration);
   
   -- Deallocates the Configuration external structure
   
   use type Interfaces.C.int;
   
   type TLS_Client_Configuration is 
     limited new TLS_Configuration with
      record
         Session_Storage_FD: Interfaces.C.int := -1;
         -- If Session_Storage is set, 
      end record;
   
   overriding
   procedure Finalize (Configuration: in out TLS_Client_Configuration);
   
   -- Closes Session_Storage_FD and then dispatches up
   
   type TLS_Server_Configuration is 
     limited new TLS_Configuration with null record;
   
   
end INET.TLS;
