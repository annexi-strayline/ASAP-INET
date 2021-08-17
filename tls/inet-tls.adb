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

with Ada.Directories;
with Ada.Unchecked_Deallocation;
with Interfaces.C.Strings;

with INET.Internal.TLS;
with INET.Internal.OS_Constants;

pragma External_With ("inet-internal-tls-sys.c");

package body INET.TLS is
   
   function close (fd: Interfaces.C.int) return Interfaces.C.int
   with Import => True, Convention => C, External_Name => "close";
   
   -- close(2) (libc)
   
   --
   -- TLS_Security_Data
   --
   
   ---------------
   -- Load_File --
   ---------------
   
   function Load_File (Path: String) return TLS_Security_Data is
     (Load_File (Path => Path, Password => ""));
   
   ----------------------------------------------------------------------
   
   function Load_File (Path: String; Password: String) 
                      return TLS_Security_Data
   is
      use Interfaces.C;
      use Interfaces.C.Strings;
      
      use type Security_Data_Pointers.Pointer;
      
      function tls_load_file (file: in char_array;
                              len :    out size_t;
                              password: in chars_ptr)
                             return Security_Data_Pointers.Pointer
      with Import => True, Convention => C, External_Name => "tls_load_file";
      
      -- We want to pass NULL to password if there is no password, rather than
      -- an "empty" string.
      
      password_copy: aliased char_array := To_C (Password);
      password_ptr : constant chars_ptr 
        := (if Password'Length = 0 then 
               Null_Ptr 
            else 
               To_Chars_Ptr (password_copy'Unchecked_Access));
      -- We promise that tls_load_file is not going to go running around with
      -- a pointer to password_copy!
   begin
      if Path'Length = 0 then
         raise Constraint_Error with "TLS_Security_Data.Load_File: "
           &                         "Path is an empty string.";
      end if;
      
      return New_Sec_Data: TLS_Security_Data (Memory) do
         New_Sec_Data.Ada_Allocation := null;
         New_Sec_Data.Data := tls_load_file 
           (file     => To_C (Path),
            len      => New_Sec_Data.Length,
            password => password_ptr);
         
         if New_Sec_Data.Data = null then
            raise TLS_Error with "Failed to load TLS_Security_Data from file "
                 & Path;
         end if;
      end return;
   end Load_File;
   
   
   --------------------
   -- Associate_File --
   --------------------
   
   function Associate_File (Path: String) return TLS_Security_Data is
      use UBS;
   begin
      if Path'Length = 0 then
         raise Constraint_Error with "TLS_Security_Data.Associate_File: "
           &                         "Path is an empty string.";
      end if;
      
      return TLS_Security_Data'(Ada.Finalization.Limited_Controlled with
                                Format => File,
                                Path   => To_Unbounded_String (Path));
   end Associate_File;
   
   -------------------
   -- Private_Write --
   -------------------
   
   -- To be used by the implementation of 'Output, but clearly noy invokable by
   -- any client of this package.
   
   procedure Private_Write
     (Stream: not null access Ada.Streams.Root_Stream_Type'Class;
      Data  : in TLS_Security_Data)
   is
      -- Note that it shouldn't be possible to have a TLS_Security_Data object
      -- that is not initialized coming into Write
      
      procedure Write_File with Inline is
         use UBS;
      begin
         Unbounded_String'Write (Stream, Data.Path);
         
      end Write_File;
      
      procedure Write_Data with Inline is
         use Interfaces;
         use Interfaces.C;
         use Security_Data_Pointers;
         
         Element_Pointer: Pointer := Data.Data;
      begin
         size_t'Write (Stream, Data.Length);
         
         -- We don't want to use Value here to return a copy of the underlying
         -- array because it is potentially quite large. Better to copy out
         -- one element at a time
         
         for I in 1 .. Data.Length loop
            Security_Data_Element'Write (Stream, Element_Pointer.all);
            Increment (Element_Pointer);
         end loop;
      end Write_Data;
      
   begin
      case Data.Format is
         when File   => Write_File;
         when Memory => Write_Data;
      end case;
   end Private_Write;
   
   ------------
   -- Output --
   ------------
   
   -- Essentially just the default implementation. We have to re-write it so
   -- that we could make it available it without also making available 
   -- 'Read/'Write.
   
   procedure Output
     (Stream: not null access Ada.Streams.Root_Stream_Type'Class;
      Data  : in TLS_Security_Data)
   is begin
      -- First write out the discriminant, and then dispatch to Private_Write
      Security_Data_Format'Write (Stream, Data.Format);
      Private_Write (Stream, Data);
   end Output;
   
   ------------------
   -- Private_Read --
   ------------------
   
   -- To be used by the implementation of 'Output, but clearly noy invokable by
   -- any client of this package. This is important because 'Read is not
   -- available for TLS_Security_Data, only 'Input is. If 'Read was available,
   -- it would be possible to overwrite an existing TLS_Security_Data object,
   -- which would potentially cause a memory leak. Of course since the Data
   -- parameter is of "out", we wouldn't be able to check on the state of
   -- Data besides reading the discriminent
   
   procedure Private_Read
     (Stream: not null access Ada.Streams.Root_Stream_Type'Class;
      Data  : out TLS_Security_Data)
   is
      procedure Read_File with Inline is
         use UBS;
      begin
         Unbounded_String'Read (Stream, Data.Path);
      end Read_File;
      
      procedure Read_Data with Inline is
         use Interfaces;
         use Interfaces.C;
         use Security_Data_Pointers;
      begin
         -- Start with the length
         size_t'Read (Stream, Data.Length);
         
         if Data.Length = 0 then
            -- There is never a case where this is useful, and there is no
            -- normal explaination for this happening
            
            raise Constraint_Error with "Input of an empty " 
              &                         "TLS_Security_Data object is not "
              &                         "acceptable.";
         end if;
         
         -- After this point possible errors will be Storage_Error or End_Error.
         -- Any successful allocation will still be freed during finalization
         -- of the return object in Input
         
         Data.Ada_Allocation := new Raw_Security_Data (1 .. Data.Length);
         Data.Data := Data.Ada_Allocation(1)'Access;
         
         for Element of Data.Ada_Allocation.all loop
            Security_Data_Element'Read (Stream, Element);
         end loop;
         
      end Read_Data;
      
   begin
      case Data.Format is
         when File   => Read_File;
         when Memory => Read_Data;
      end case;
   end Private_Read;
   
   -----------
   -- Input --
   -----------
   
   -- Essentially just the default implementation. We have to re-write it so
   -- that we could make it available it without also making available 
   -- 'Read/'Write.
   
   function Input (Stream: not null access Ada.Streams.Root_Stream_Type'Class)
                  return TLS_Security_Data
   is
      Selected_Format: Security_Data_Format;
   begin
      -- First read in the dicriminant, and then hand-craft an appropriate
      -- return object, and pass it to Private_Read to fill in the rest
      Security_Data_Format'Read (Stream, Selected_Format);
      
      return In_Data: TLS_Security_Data (Selected_Format) do
         Private_Read (Stream, In_Data);
      end return;
   end Input;
   
   --------------
   -- Finalize --
   --------------
   
   procedure Finalize (Data: in out TLS_Security_Data) is
      use Security_Data_Pointers;
      
      procedure Free is new Ada.Unchecked_Deallocation 
        (Object => Raw_Security_Data, Name => Security_Data_Allocation);
      
      procedure tls_unload_file (buf: Security_Data_Pointers.Pointer;
                                 len: Interfaces.C.size_t)
      with Import => True, Convention => C, External_Name => "tls_unload_file";
      
   begin
      -- If we have a "Memory" format, we need to free it. If we are freeing
      -- libtls, it will handle zeroing the memory. Otherwise we need to do
      -- that for the Ada allocation directly
      
      -- Make sure any format changes are found by the compiler!
      case Data.Format is
         when File =>
            return;
            
         when Memory =>
            null;
      end case;
      
      if Data.Ada_Allocation = null then
         -- libtls allocation

         tls_unload_file (buf => Data.Data, len => Data.Length);
         Data.Length := 0;
         Data.Data   := null;
         
      else
         -- Recall: in this case, the actual block of data is allocated to
         -- Data.Ada_Allocation, and Data.Data points at the first element
         -- of that allocation.
         
         Data.Ada_Allocation.all := (others => 0);
         Data.Length             := 0;
         Data.Data               := null;
         Free (Data.Ada_Allocation);
      end if;
   end Finalize;
   
   --
   -- TLS_Session_ID
   --
   
   -----------
   -- Valid --
   -----------
   
   function Valid (ID: TLS_Session_ID) return Boolean is (ID.Initialized);
   
   ------------------
   -- Randomize_ID --
   ------------------
   
   procedure Randomize_ID (ID: out TLS_Session_ID) is
   begin
      INET.Internal.TLS.Cryptographic_Randomize (ID.ID);
      ID.Initialized := True;
   end Randomize_ID;
   
   --
   -- TLS_Ticket_Key
   --
   
   -----------
   -- Valid --
   -----------
   
   function Valid (Key: TLS_Ticket_Key) return Boolean is (Key.Initialized);
   
   -------------------
   -- Randomize_Key --
   -------------------
   
   procedure Randomize_Key (Key: out TLS_Ticket_Key) is
   begin
      INET.Internal.TLS.Cryptographic_Randomize (Key.Key);
      INET.Internal.TLS.Cryptographic_Randomize (Key.Revision);
      Key.Initialized := True;
   end Randomize_Key;
   
   --------------
   -- Zero_Key --
   --------------
   
   procedure Zero_Key (Key: out TLS_Ticket_Key) is
   begin
      Key.Initialized := False;
      Key.Revision := 0;
      Key.Key      := (others => 0);
   end Zero_Key;
   
   --
   -- TLS_Configuration
   --
   
   -- Star of the show
   
   ----------------------------
   -- Raise_TLS_Config_Error --
   ----------------------------
   
   procedure Raise_TLS_Config_Error (Configuration: in TLS_Configuration'Class;
                                     Preamble     : in String)
   with No_Return is
      use Interfaces.C.Strings;
      
      function tls_config_error (config: Configuration_Handle)
                                return chars_ptr 
      with Import => True, Convention => C,
        External_Name => "tls_config_error";
      
      Error_Message_Ptr: constant chars_ptr
        := tls_config_error (Configuration.Handle);
      
      Error_Message: constant String
        := (if Error_Message_Ptr /= Null_Ptr then 
               Value (Error_Message_Ptr)
            else
               "[No error message available from libtls]");
   begin
      raise TLS_Configuration_Error with Preamble & ": " & Error_Message;
   end Raise_TLS_Config_Error;
   
   --------------------------
   -- Acceptable_Protocols --
   --------------------------
   
   procedure Acceptable_Protocols
     (Configuration: in out TLS_Configuration;
      Protocols    : in     TLS_Protocol_Selection)
   is
      use Interfaces;
      use Interfaces.C;
      
      TLS_PROTOCOL_TLSv1_0: constant Unsigned_32 with
          Import => True, Convention => C, 
          External_Name => "__inet_internal_tls_sys_TLS_PROTOCOL_TLSv1_0";
      
      TLS_PROTOCOL_TLSv1_1: constant Unsigned_32 with
          Import => True, Convention => C, 
          External_Name => "__inet_internal_tls_sys_TLS_PROTOCOL_TLSv1_1";
      
      TLS_PROTOCOL_TLSv1_2: constant Unsigned_32 with
          Import => True, Convention => C, 
          External_Name => "__inet_internal_tls_sys_TLS_PROTOCOL_TLSv1_2";
      
      TLS_PROTOCOL_TLSv1_3: constant Unsigned_32 with
          Import => True, Convention => C, 
          External_Name => "__inet_internal_tls_sys_TLS_PROTOCOL_TLSv1_3";
      
      function tls_config_set_protocols (config   : Configuration_Handle;
                                         protocols: Unsigned_32)
                                        return int
      with Import => True, Convention => C,
        External_Name => "tls_config_set_protocols";
      
      Protocol_Set: Unsigned_32 := 0;
      Retval: int;
   begin
      if Protocols.TLS_v1_0 then
         Protocol_Set := TLS_PROTOCOL_TLSv1_0;
      end if;
      
      if Protocols.TLS_v1_1 then
         Protocol_Set := Protocol_Set or TLS_PROTOCOL_TLSv1_1;
      end if;
      
      if Protocols.TLS_v1_2 then
         Protocol_Set := Protocol_Set or TLS_PROTOCOL_TLSv1_2;
      end if;
      
      if Protocols.TLS_v1_3 then
         Protocol_Set := Protocol_Set or TLS_PROTOCOL_TLSv1_3;
      end if;
      
      Retval := tls_config_set_protocols (config    => Configuration.Handle,
                                          protocols => Protocol_Set);
      
      if Retval /= 0 then
         Raise_TLS_Config_Error 
           (Configuration, "Failed to set accepted protocols");
      end if;
      
   end Acceptable_Protocols;
   
   -----------------------
   -- Root_Certificates --
   -----------------------
   
   procedure Root_Certificates (Configuration: in out TLS_Configuration;
                                Root_CA_Certs: in     TLS_Security_Data'Class)
   is
      use Interfaces.C;
      
      function tls_config_set_ca_file (config : Configuration_Handle;
                                       ca_file: char_array)
                                      return int
      with Import => True, Convention => C,
        External_Name => "tls_config_set_ca_file";
      
      -- ca_file is a path to a certificate chain file
      
      function tls_config_set_ca_path (config: Configuration_Handle;
                                       ca_path: char_array)
                                      return int
      with Import => True, Convention => C,
        External_Name => "tls_config_set_ca_path";
      
      -- ca_path is a path to a directory containing all the ca certificates
      
      function tls_config_set_ca_mem (config: Configuration_Handle;
                                      cert  : Security_Data_Pointers.Pointer;
                                      len   : size_t)
                                     return int
      with Import => True, Convention => C,
        External_Name => "tls_config_set_ca_mem";
      
      Retval: int;
   begin
      case Root_CA_Certs.Format is
         when File =>
            declare
               use Ada.Directories;
               
               Full_Path: constant String
                 := Full_Name (UBS.To_String (Root_CA_Certs.Path));
            begin
               if not Exists (Full_Path) then
                  raise TLS_Configuration_Error with
                    "Root CA certificates path does not exist";
               end if;
               
               case Kind (Full_Path) is
                  when Directory =>
                     Retval := tls_config_set_ca_path
                       (config  => Configuration.Handle,
                        ca_path => To_C (Full_Path));
                     
                  when Ordinary_File =>
                     Retval := tls_config_set_ca_file
                       (config  => Configuration.Handle,
                        ca_file => To_C (Full_Path));
                     
                  when Special_File =>
                     raise TLS_Configuration_Error with
                       "Root CA certificates path cannot point to a "
                       & "special file.";
               end case;
               
            end;
         when Memory =>
            Retval := tls_config_set_ca_mem 
              (config => Configuration.Handle,
               cert   => Root_CA_Certs.Data,
               len    => Root_CA_Certs.Length);
      end case;
      
      if Retval /= 0 then
         Raise_TLS_Config_Error (Configuration, 
                                 "Failed to load root CA certificates");
      end if;
      
   exception
      when Ada.Directories.Name_Error =>
         raise TLS_Configuration_Error with
           "Root CA certificate path is invalid";
   end Root_Certificates;
   
   -----------------------------------
   -- Generic_Set_Security_Property --
   -----------------------------------
   
   generic
      with function set_file (config: Configuration_Handle;
                              path: Interfaces.C.char_array)
                             return Interfaces.C.int;
   
      with function set_mem (config: Configuration_Handle;
                             data  : Security_Data_Pointers.Pointer;
                             len   : Interfaces.C.size_t)
                            return Interfaces.C.int;
   
      Error_Preamble: in String;
   
   procedure Generic_Set_Security_Property
     (Configuration: in out TLS_Configuration;
      Data         : in     TLS_Security_Data'Class);
   
   procedure Generic_Set_Security_Property
     (Configuration: in out TLS_Configuration;
      Data         : in     TLS_Security_Data'Class)
   is
      use Interfaces.C;
      
      Retval: int;
   begin
      case Data.Format is
         when File =>
            Retval := set_file 
              (config => Configuration.Handle,
               path   => To_C (UBS.To_String (Data.Path)));
         when Memory =>
            Retval := set_mem
              (config => Configuration.Handle,
               data   => Data.Data,
               len    => Data.Length);
      end case;
      
      if Retval /= 0 then
         Raise_TLS_Config_Error (Configuration, Error_Preamble);
      end if;
   end Generic_Set_Security_Property;
   
   
   --------------
   -- Key_Pair --
   --------------
   
   procedure Key_Pair (Configuration: in out TLS_Configuration;
                       Certificate  : in     TLS_Security_Data'Class;
                       Key          : in     TLS_Security_Data'Class)
   is
      use Interfaces.C;
      
      function tls_config_set_cert_file (config: Configuration_Handle;
                                         key_file: char_array)
                                        return int
      with Import => True, Convention => C,
        External_Name => "tls_config_set_cert_file";
      
      function tls_config_set_cert_mem (config: Configuration_Handle;
                                        key   : Security_Data_Pointers.Pointer;
                                        len   : size_t)
                                       return int
      with Import => True, Convention => C,
        External_Name => "tls_config_set_cert_mem";
      
      procedure Set_Cert is new Generic_Set_Security_Property
        (set_file => tls_config_set_cert_file,
         set_mem  => tls_config_set_cert_mem,
         Error_Preamble => "Failed to set keypair certificate");
      
      
      function tls_config_set_key_file (config: Configuration_Handle;
                                        key_file: char_array)
                                       return int
      with Import => True, Convention => C,
        External_Name => "tls_config_set_key_file";
      
      function tls_config_set_key_mem (config: Configuration_Handle;
                                       key   : Security_Data_Pointers.Pointer;
                                       len   : size_t)
                                      return int
      with Import => True, Convention => C,
        External_Name => "tls_config_set_key_mem";
      
      procedure Set_Key is new Generic_Set_Security_Property
        (set_file => tls_config_set_key_file,
         set_mem  => tls_config_set_key_mem,
         Error_Preamble => "Failed to set private key");
      
   begin
      Set_Cert (Configuration => Configuration,
                Data          => Certificate);
      
      Set_Key (Configuration => Configuration,
               Data          => Key);
   end Key_Pair;
   
   ----------------
   -- Clear_Keys --
   ----------------
   
   procedure Clear_Keys (Configuration: in out TLS_Configuration) is
      procedure tls_config_clear_keys (config: in Configuration_Handle) with
        Import => True, Convention => C,
        External_Name => "tls_config_clear_keys";
   begin
      tls_config_clear_keys (Configuration.Handle);
   end Clear_Keys;
   
   ---------------------------------
   -- Certificate_Revocation_List --
   ---------------------------------
   
   function tls_config_set_crl_file (config: Configuration_Handle;
                                     crl_file: Interfaces.C.char_array)
                                    return Interfaces.C.int
   with Import => True, Convention => C,
     External_Name => "tls_config_set_crl_file";
   
   function tls_config_set_crl_mem (config: Configuration_Handle;
                                    crl   : Security_Data_Pointers.Pointer;
                                    len   : Interfaces.C.size_t)
                                   return Interfaces.C.int
   with Import => True, Convention => C,
     External_Name => "tls_config_set_crl_mem";
   
   procedure Set_CRL is new Generic_Set_Security_Property
     (set_file => tls_config_set_crl_file,
      set_mem  => tls_config_set_crl_mem,
      Error_Preamble => "Unable to set Certificate Revocation List");
   
   procedure Certificate_Revocation_List 
     (Configuration  : in out TLS_Configuration;
      Revocation_List: in     TLS_Security_Data'Class)
     renames Set_CRL;
   
   -----------------
   -- OCSP_Staple --
   -----------------
   
   function tls_config_set_ocsp_staple_file 
     (config     : Configuration_Handle;
      staple_file: Interfaces.C.char_array)
     return Interfaces.C.int
   with Import => True, Convention => C,
     External_Name => "tls_config_set_ocsp_staple_file";
   
   function tls_config_set_ocsp_staple_mem 
     (config: Configuration_Handle;
      staple: Security_Data_Pointers.Pointer;
      len   : Interfaces.C.size_t)
     return Interfaces.C.int
   with Import => True, Convention => C,
     External_Name => "tls_config_set_ocsp_staple_mem";
   
   procedure OCSP_Staple_Actual is new Generic_Set_Security_Property
     (set_file => tls_config_set_ocsp_staple_file,
      set_mem  => tls_config_set_ocsp_staple_mem,
      Error_Preamble => "Unable to set OSCP Staple");
   
   procedure OCSP_Staple (Configuration: in out TLS_Configuration;
                          Staple       : in     TLS_Security_Data'Class)
     renames OCSP_Staple_Actual;
   
   -------------------------
   -- Require_OCSP_Staple --
   -------------------------
   
   procedure Require_OCSP_Staple (Configuration: in out TLS_Configuration) is
      procedure tls_config_ocsp_require_stapling (config: Configuration_Handle)
      with Import => True, Convention => C,
        External_Name => "tls_config_ocsp_require_stapling";
   begin
      tls_config_ocsp_require_stapling (Configuration.Handle);
   end Require_OCSP_Staple;
   
   ---------------------
   -- Supported_ALPNs --
   ---------------------
   
   procedure Supported_ALPNs (Configuration: in out TLS_Configuration;
                              ALPN_List    : in     String)
   is
      use Interfaces.C;
      
      function tls_config_set_alpn (config: Configuration_Handle;
                                    alpn  : char_array)
                                   return int 
      with Import => True, Convention => C,
        External_Name => "tls_config_set_alpn";
      
      Retval: int;
   begin
      Retval := tls_config_set_alpn (config => Configuration.Handle,
                                     alpn   => To_C (ALPN_List));
      
      if Retval /= 0 then
         Raise_TLS_Config_Error (Configuration,
                                 "Supported ALPNs could not be set");
      end if;
   end Supported_ALPNs;
   
   -------------------------
   -- Get_External_Handle --
   -------------------------
   
   procedure Get_External_Handle (Configuration: in     TLS_Configuration;
                                  Handle       :    out INET_Extension_Handle)
   is begin
      Handle := INET_Extension_Handle (Configuration.Handle);
   end Get_External_Handle;
   
   
   ----------------
   -- Initialize --
   ----------------
   
   procedure Initialize (Configuration: in out TLS_Configuration) is
      
      function tls_config_new return Configuration_Handle with
        Import => True, Convention => C,
        External_Name => "tls_config_new";
      
   begin
      Configuration.Handle := tls_config_new;
      
      if Configuration.Handle = Null_Configuration_Handle then
         raise TLS_Configuration_Error with
           "Unable to allocate new tls_session structure";
      end if;
   end Initialize;
   
   --------------
   -- Finalize --
   --------------
   
   procedure Finalize (Configuration: in out TLS_Configuration) is
      procedure tls_config_free (config: Configuration_Handle) with
        Import => True, Convention => C, External_Name => "tls_config_free";
   begin
      tls_config_free  (Configuration.Handle);
   end Finalize;
   
   --
   -- TLS_Client_Configuration
   --
   
   ---------------------
   -- Session_Storage --
   ---------------------
   
   procedure Session_Storage
     (Configuration: in out TLS_Client_Configuration;
      Path         : in     String)
   is
      use Interfaces.C;
      use INET.Internal.OS_Constants;
      
      function open (path: char_array; flags: int)
                    return int
      with Import => True, Convention => C, External_Name => "open";
      
      -- Open(2) (libc)
      
      function tls_config_set_session_fd (config    : Configuration_Handle;
                                          session_fd: int)
                                         return int
      with Import => True, Convention => C, 
        External_Name => "tls_config_set_session_fd";
      
      SS_FD: int renames Configuration.Session_Storage_FD;
      
      Retval, Discard: int;
   begin
      if SS_FD >= 0 then
         raise Program_Error with
           "Cannot invoke TLS_Configration.Session_Storage more than once "
              & "per TLS_Configuration object.";
      end if;
      
      SS_FD := open (path => To_C (Path), flags => O_RDWR + O_CLOEXEC);
      
      if SS_FD < 0 then
         raise TLS_Configuration_Error with 
           "Failed to open session storage file. "
           & "errno =" & int'Image (Get_Errno);
      end if;
      
      Retval := tls_config_set_session_fd (config     => Configuration.Handle,
                                           session_fd => SS_FD);
      
      if Retval /= 0 then
         Raise_TLS_Config_Error 
           (Configuration, "Failed to set session storage file");
         Discard := close (SS_FD);
         SS_FD := -1;
      end if;
      
   end Session_Storage;
   
   --------------
   -- Finalize --
   --------------
   
   procedure Finalize (Configuration: in out TLS_Client_Configuration) is
      Discard: Interfaces.C.int;
   begin
      Discard := close (Configuration.Session_Storage_FD);
      TLS_Configuration (Configuration).Finalize;
   end Finalize;
   
   --
   -- TLS_Server_Configuration
   --
   
   ----------------------
   -- Session_Lifetime --
   ----------------------
   
   procedure Session_Lifetime (Configuration: in out TLS_Server_Configuration;
                               Lifetime     : in     Duration)
   is 
      use Interfaces.C;
      
      function tls_config_set_session_lifetime
        (config: Configuration_Handle; lifetime: int)
        return int
      with Import => True, Convention => C,
        External_Name => "tls_config_set_session_lifetime";
      
      Retval: int;
      Lifetime_Secs: int := int (Lifetime);
   begin
      Retval := tls_config_set_session_lifetime 
        (config   => Configuration.Handle,
         lifetime => Lifetime_Secs);
      
      if Retval /= 0 then
         Raise_TLS_Config_Error
           (Configuration, "Failed to set session lifetime");
      end if;
      
   end Session_Lifetime;
   
   ----------------
   -- Session_ID --
   ----------------
   
   procedure Session_ID (Configuration: in out TLS_Server_Configuration;
                         ID           : in     TLS_Session_ID)
   is 
      use Interfaces.C;
      
      function tls_config_set_session_id 
        (config    : Configuration_Handle;
         session_id: Session_ID_Data;
         len       : size_t)
        return int
      with Import => True, Convention => C,
        External_Name => "tls_config_set_session_id";
      
      Retval: int;
   begin
      if not ID.Initialized then
         raise Program_Error with "Attempt to set Session_ID with invalid "
           & "TLS_Session_ID";
      end if;
      
      Retval := tls_config_set_session_id
        (config     => Configuration.Handle,
         session_id => ID.ID,
         len        => ID.ID'Length);
      
      if Retval /= 0 then
         Raise_TLS_Config_Error
           (Configuration, "Failed to set session ID");
      end if;
   end Session_ID;
   
   --------------------
   -- Add_Ticket_Key --
   --------------------
   
   procedure Add_Ticket_Key (Configuration: in out TLS_Server_Configuration;
                             Key          : in     TLS_Ticket_Key)
   is
      use Interfaces.C;
      
      function tls_config_add_ticket_key
        (config: Configuration_Handle;
         keyrev: Key_Revision;
         key   : Ticket_Key_Data;
         keylen: size_t)
        return int
      with Import => True, Convention => C,
        External_Name => "tls_config_add_ticket_key";
      
      Retval: int;
   begin
      if not Key.Initialized then
         raise Program_Error with "Attempt to add invalid TLS_Ticket_Key";
      end if;
      
      Retval := tls_config_add_ticket_key
        (config => Configuration.Handle,
         keyrev => Key.Revision,
         key    => Key.Key,
         keylen => Key.Key'Length);
      
      if Retval /= 0 then
         Raise_TLS_Config_Error
           (Configuration, "Failed to add new ticket key");
      end if;
   end Add_Ticket_Key;
   
   -------------------
   -- Verify_Client --
   -------------------
   
   procedure Verify_Client (Configuration: in out TLS_Server_Configuration) is
      procedure tls_config_verify_client (config: in Configuration_Handle) with
        Import => True, Convention => C,
        External_Name => "tls_config_verify_client";
   begin
      tls_config_verify_client (Configuration.Handle);
   end Verify_Client;
   
   
end INET.TLS;
