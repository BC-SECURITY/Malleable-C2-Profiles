https-certificate {
set keystore "";
set password "";
}

set sleeptime	"48000";
set jitter	"65";
set useragent	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36";
set dns_idle	"1.1.1.1";
set maxdns	"235";

post-ex {
set spawnto_x86 "%windir%\\syswow64\\gpresult.exe";
set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";
}

http-get {

set uri "/search";

client {
header "Host" "duckduckgo.com";
header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
header "Cookie" "ax=v176-5";

metadata {
base64url;
parameter "q";
}

parameter "qs" "ramen";
parameter "t" "h_";
parameter "ia" "web";
}

server {

header "Cache-Control" "private, max-age=0";
        header "Content-Type" "text/html; charset=utf-8";
        header "Vary" "Accept-Encoding";
        header "Server" "Microsoft-IIS/8.5";
        header "Connection" "close";

output {
netbios;
prepend "<!DOCTYPE html><html lang=\"en_US\" class=\"no-js has-zcm\"><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"><title>ramen at DuckDuckGo</title><link rel=\"stylesheet\" href=\"/s1798.css\" type=\"text/css\"><link rel=\"stylesheet\" href=\"/r1798.css\" type=\"text/css\"><meta name=\"robots\" content=\"noindex,nofollow\"><meta name=\"referrer\" content=\"origin\"><meta name=\"apple-mobile-web-app-title\" content=\"ramen\"><link rel=\"shortcut icon\" href=\"/favicon.ico\" type=\"image/x-icon\" sizes=\"16x16 24x24 32x32 64x64\"/><link id=\"icon60\" rel=\"apple-touch-icon\" href=\"/assets/icons/meta/DDG-iOS-icon_60x60.png?v=2\"/><link id=\"icon76\" rel=\"apple-touch-icon\" sizes=\"76x76\" href=\"/assets/icons/meta/DDG-iOS-icon_76x76.png?v=2\"/><link id=\"icon120\" rel=\"apple-touch-icon\" sizes=\"120x120\" href=\"/assets/icons/meta/DDG-iOS-icon_120x120.png?v=2\"/><link id=\"icon152\" rel=\"apple-touch-icon\" sizes=\"152x152\" href=\"/assets/icons/meta/DDG-iOS-icon_152x152.png?v=2\"/><link rel=\"image_src\" href=\"/assets/icons/meta/DDG-icon_256x256.png\"/><script type=\"text/javascript\">var ct,fd,fq,it,iqa,iqm,iqs,iqp,iqq,qw,dl,ra,rv,rad,r1hc,r1c,r2c,r3c,rfq,rq,rds,rs,rt,rl,y,y1,ti,tig,iqd,locale,settings_js_version='s2473.js',is_twitter='',rpl=1;fq=0;fd=1;it=0;iqa=0;iqbi=0;iqm=0;iqs=0;iqp=0;iqq=0;qw=1;dl='en';ct='US';iqd=0;r1hc=0;r1c=0;r3c=0;rq='ramen';rqd=\"ramen\";rfq=0;rt='D';ra='h_';rv='';rad='';rds=30;rs=0;spice_version='1397';spice_paths='{}';locale='en_US';settings_url_params={};rl='us-en';rlo=0;df='';ds='';sfq='';iar='';vqd='3-2495358492768631519045579927498153959-79951267394787688665837204955443138657';safe_ddg=0;;</script><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" /><meta name=\"HandheldFriendly\" content=\"true\" /><meta name=\"apple-mobile-web-app-capable\" content=\"no\" /></head><body class=\"body--serp\"><input id=\"state_hidden\" name=\"state_hidden\" type=\"text\" size=\"1\"><span class=\"hide\">Ignore this box please.</span><div id=\"spacing_hidden_wrapper\"><div id=\"spacing_hidden\"></div></div><script type=\"text/javascript\" src=\"/lib/l113.js\"></script><script type=\"text/javascript\" src=\"/locale/en_US/duckduckgo14.js\"></script><script type=\"text/javascript\" src=\"/util/u366.js\"></script><script type=\"text/javascript\" src=\"/d2641.js\"></script><div class=\"site-wrapper  js-site-wrapper\"><div class=\"welcome-wrap js-welcome-wrap\"></div><div id=\"header_wrapper\" class=\"header-wrap js-header-wrap\"><div id=\"header\" class=\"header  cw\"><div class=\"header__search-wrap\"><a tabindex=\"-1\" href=\"/?t=h_\" class=\"header__logo-wrap js-header-logo\"><span class=\"header__logo js-logo-ddg\">DuckDuckGo</span></a><div class=\"header__content  header__search\"><form id=\"search_form\" class=\"search--adv  search--header  js-search-form\" name=\"x\" action=\"/\"><input type=\"text\" name=\"q\" tabindex=\"1\" autocomplete=\"off\" id=\"search_form_input\" class=\"search__input search__input--adv js-search-input\" value=\"ramen\"><input id=\"search_form_input_clear\" class=\"search__clear  js-search-clear\" type=\"button\" tabindex=\"3\" value=\"X\"/><input id=\"search_button\" class=\"search__button  js-search-button\" type=\"submit\" tabindex=\"2\" value=\"S\" /><a id=\"search_dropdown\" class=\"search__dropdown\" href=\"javascript:;\" tabindex=\"4\"></a><div id=\"search_elements_hidden\" class=\"search__hidden  js-search-hidden\"></div></form></div></div><div id=\"duckbar\" class=\"zcm-wrap  zcm-wrap--header  is-noscript-hidden\"></div></div><div class=\"header--aside js-header-aside\"></div></div><div id=\"zero_click_wrapper\" class=\"zci-wrap\"></div><div id=\"vertical_wrapper\" class=\"verticals\"></div><div id=\"web_content_wrapper\" class=\"content-wrap \"><div class=\"serp__top-right  js-serp-top-right\"></div><div class=\"serp__bottom-right  js-serp-bottom-right\"><div class=\"js-feedback-btn-wrap\"></div></div><div class=\"cw\"><div id=\"links_wrapper\" class=\"serp__results js-serp-results\"><div class=\"results--main\"><div class=\"search-filters-wrap\"><div class=\"js-search-filters search-filters\"></div></div><noscript><meta http-equiv=\"refresh\" content=\"0;URL=/html?q=ramen\"><link href=\"/css/noscript.css\" rel=\"stylesheet\" type=\"text/css\"><div class=\"msg msg--noscript\"><p class=\"msg-title--noscript\">You are being redirected to the non-JavaScript site.</p>Click <a href=\"/html/?q=ramen\">here</a> if it doesn't happen automatically.</div></noscript><div id=\"message\" class=\"results--message\"></div><div class=\"ia-modules js-ia-modules\"></div><div id=\"ads\" class=\"results--ads results--ads--main is-hidden js-results-ads\"></div><div id=\"links\" class=\"results is-hidden js-results\"></div></div><div class=\"results--sidebar js-results-sidebar\"><div class=\"sidebar-modules js-sidebar-modules\"></div><div class=\"is-hidden js-sidebar-ads\"></div></div></div></div></div><div id=\"bottom_spacing2\"> </div></div><script type=\"text/javascript\"></script><script type=\"text/JavaScript\">function nrji() {nrj('/t.js?q=ramen&t=D&l=us-en&s=0&dl=en&ct=US&ss_mkt=us&p_ent=&ex=-1');DDG.search.adSource='dsu';nrj('/d.js?q=ramen&t=D&l=us-en&s=0&a=h_&dl=en&ct=US&ss_mkt=us&vqd=3-2495358492768631519045579927498153959-79951267394787688665837204955443138657&p_ent=&ex=-1&sp=0');DDH.wikipedia_fathead=DDH.wikipedia_fathead||{};DDH.wikipedia_fathead.meta={\"src_name\":\"Wikipedia\",\"designer\":null,\"live_date\":null,\"dev_milestone\":\"live\",\"js_callback_name\":\"wikipedia\",\"unsafe\":0,\"src_url\":null,\"src_domain\":\"en.wikipedia.org\",\"dev_date\":null,\"status\":\"live\",\"producer\":null,\"is_stackexchange\":null,\"attribution\":null,\"production_state\":\"online\",\"blockgroup\":null,\"description\":\"Wikipedia\",\"signal_from\":\"wikipedia_fathead\",\"maintainer\":{\"github\":\"duckduckgo\"},\"perl_module\":\"DDG::Fathead::Wikipedia\",\"repo\":\"fathead\",\"topic\":[\"productivity\"],\"tab\":\"About\",\"name\":\"Wikipedia\",\"id\":\"wikipedia_fathead\",\"example_query\":\"nikola tesla\",\"created_date\":null,\"src_id\":1,\"src_options\":{\"skip_image_name\":0,\"is_wikipedia\":1,\"is_fanon\":0,\"src_info\":\"\",\"skip_abstract\":0,\"skip_qr\":\"\",\"language\":\"en\",\"is_mediawiki\":1,\"source_skip\":\"\",\"skip_end\":\"0\",\"skip_icon\":0,\"skip_abstract_paren\":0,\"min_abstract_length\":\"20\",\"directory\":\"\"},\"developer\":[{\"type\":\"ddg\",\"url\":\"http://www.duckduckhack.com\",\"name\":\"DDG Team\"}]};;};DDG.ready(nrji, 1);</script><script src=\"/g2157.js\"></script></body></html>";
append "<div class=\"footer\" style=\"display: block;\"><div class=\"footer__left\"><div class=\"footer_cards\"><a class=\"footer__card js-footer-card bg-clr--white\" href=\"https://duckduckgo.com/traffic/\" data-id=\"traffic\"><img class=\"footer__card__icon\" src=\"/assets/icons/traffic.svg\" alt=\"\" aria-hidden=\"true\"><h3 class=\"footer__card__title tx-clr--slate\">30 Billion Searches</h3><p class=\"footer__text\">We get a ton of searches, and all of them are anonymous.</p></a><a class=\"footer__card js-footer-card bg-clr--white\" href=\"https://duckduckgo.com/newsletter\" data-id=\"su\"><img class=\"footer__card__icon\" src=\"/assets/icons/newsletter.svg\" alt=\"\" aria-hidden=\"true\"><h3 class=\"footer__card__title tx-clr--slate\">Our Crash Course</h3><p class=\"footer__text\">Take our Privacy Crash Course and learn about online privacy.</p></a><a class=\"footer__card js-footer-card bg-clr--white\" href=\"https://duckduckgo.com/bang\" data-id=\"ba\"><img class=\"footer__card__icon\" src=\"/assets/icons/bangs.svg\" alt=\"\" aria-hidden=\"true\"><h3 class=\"footer__card__title tx-clr--slate\">Learn About Bangs</h3><p class=\"footer__text\">Discover shortcuts to go to search results on other sites.</p></a></div></div><div class=\"footer__right\"><div class=\"footer__column\"><h2 class=\"footer__title tx-clr--slate-light\">Stay Informed</h2><p class=\"footer__text\">We don't track you, but others do.</p><p class=\"footer__text\">Learn how to protect your privacy.</p><div class=\"footer__links\"><a href=\"https://spreadprivacy.com\" class=\"js-footer-link\" data-id=\"bl\"><img class=\"footer__social-icon\" src=\"/assets/icons/footer/globe.svg\" alt=\"\" aria-hidden=\"true\"></a><a href=\"https://twitter.com/duckduckgo\" class=\"js-footer-link\" data-id=\"tw\"><img class=\"footer__social-icon\" src=\"/assets/icons/footer/twr.svg\" alt=\"\" aria-hidden=\"true\"></a><a href=\"https://reddit.com/r/duckduckgo\" class=\"js-footer-link\" data-id=\"rd\"><img class=\"footer__social-icon\" src=\"/assets/icons/footer/reddit.svg\" alt=\"\" aria-hidden=\"true\"></a><a href=\"https://duckduckgo.com/newsletter\" class=\"js-footer-link\" data-id=\"nl\"><img class=\"footer__social-icon\" src=\"/assets/icons/footer/newsletter.svg\" alt=\"\" aria-hidden=\"true\"></a></div></div></div></div>";
print;
}
}
}

http-post {
    
    set uri "/Search/";
    set verb "GET";

    client {

        header "Host" "duckduckgo.com";
header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
header "Cookie" "ax=v176-5";
        
        output {
            base64url;
            parameter "p";
        }
        
        parameter "qs" "ramen";
parameter "t" "h_";
parameter "ia" "web";
        
        id {
            base64url;
            parameter "form";
        }
    }

    server {

        header "Cache-Control" "private, max-age=0";
        header "Content-Type" "text/html; charset=utf-8";
        header "Vary" "Accept-Encoding";
        header "Server" "Microsoft-IIS/8.5";
        header "Connection" "close";
        

        output {
            netbios;
            prepend "<!DOCTYPE html><html lang=\"en_US\" class=\"no-js has-zcm\"><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"><title>ramen at DuckDuckGo</title><link rel=\"stylesheet\" href=\"/s1798.css\" type=\"text/css\"><link rel=\"stylesheet\" href=\"/r1798.css\" type=\"text/css\"><meta name=\"robots\" content=\"noindex,nofollow\"><meta name=\"referrer\" content=\"origin\"><meta name=\"apple-mobile-web-app-title\" content=\"ramen\"><link rel=\"shortcut icon\" href=\"/favicon.ico\" type=\"image/x-icon\" sizes=\"16x16 24x24 32x32 64x64\"/><link id=\"icon60\" rel=\"apple-touch-icon\" href=\"/assets/icons/meta/DDG-iOS-icon_60x60.png?v=2\"/><link id=\"icon76\" rel=\"apple-touch-icon\" sizes=\"76x76\" href=\"/assets/icons/meta/DDG-iOS-icon_76x76.png?v=2\"/><link id=\"icon120\" rel=\"apple-touch-icon\" sizes=\"120x120\" href=\"/assets/icons/meta/DDG-iOS-icon_120x120.png?v=2\"/><link id=\"icon152\" rel=\"apple-touch-icon\" sizes=\"152x152\" href=\"/assets/icons/meta/DDG-iOS-icon_152x152.png?v=2\"/><link rel=\"image_src\" href=\"/assets/icons/meta/DDG-icon_256x256.png\"/><script type=\"text/javascript\">var ct,fd,fq,it,iqa,iqm,iqs,iqp,iqq,qw,dl,ra,rv,rad,r1hc,r1c,r2c,r3c,rfq,rq,rds,rs,rt,rl,y,y1,ti,tig,iqd,locale,settings_js_version='s2473.js',is_twitter='',rpl=1;fq=0;fd=1;it=0;iqa=0;iqbi=0;iqm=0;iqs=0;iqp=0;iqq=0;qw=1;dl='en';ct='US';iqd=0;r1hc=0;r1c=0;r3c=0;rq='ramen';rqd=\"ramen\";rfq=0;rt='D';ra='h_';rv='';rad='';rds=30;rs=0;spice_version='1397';spice_paths='{}';locale='en_US';settings_url_params={};rl='us-en';rlo=0;df='';ds='';sfq='';iar='';vqd='3-2495358492768631519045579927498153959-79951267394787688665837204955443138657';safe_ddg=0;;</script><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" /><meta name=\"HandheldFriendly\" content=\"true\" /><meta name=\"apple-mobile-web-app-capable\" content=\"no\" /></head><body class=\"body--serp\"><input id=\"state_hidden\" name=\"state_hidden\" type=\"text\" size=\"1\"><span class=\"hide\">Ignore this box please.</span><div id=\"spacing_hidden_wrapper\"><div id=\"spacing_hidden\"></div></div><script type=\"text/javascript\" src=\"/lib/l113.js\"></script><script type=\"text/javascript\" src=\"/locale/en_US/duckduckgo14.js\"></script><script type=\"text/javascript\" src=\"/util/u366.js\"></script><script type=\"text/javascript\" src=\"/d2641.js\"></script><div class=\"site-wrapper  js-site-wrapper\"><div class=\"welcome-wrap js-welcome-wrap\"></div><div id=\"header_wrapper\" class=\"header-wrap js-header-wrap\"><div id=\"header\" class=\"header  cw\"><div class=\"header__search-wrap\"><a tabindex=\"-1\" href=\"/?t=h_\" class=\"header__logo-wrap js-header-logo\"><span class=\"header__logo js-logo-ddg\">DuckDuckGo</span></a><div class=\"header__content  header__search\"><form id=\"search_form\" class=\"search--adv  search--header  js-search-form\" name=\"x\" action=\"/\"><input type=\"text\" name=\"q\" tabindex=\"1\" autocomplete=\"off\" id=\"search_form_input\" class=\"search__input search__input--adv js-search-input\" value=\"ramen\"><input id=\"search_form_input_clear\" class=\"search__clear  js-search-clear\" type=\"button\" tabindex=\"3\" value=\"X\"/><input id=\"search_button\" class=\"search__button  js-search-button\" type=\"submit\" tabindex=\"2\" value=\"S\" /><a id=\"search_dropdown\" class=\"search__dropdown\" href=\"javascript:;\" tabindex=\"4\"></a><div id=\"search_elements_hidden\" class=\"search__hidden  js-search-hidden\"></div></form></div></div><div id=\"duckbar\" class=\"zcm-wrap  zcm-wrap--header  is-noscript-hidden\"></div></div><div class=\"header--aside js-header-aside\"></div></div><div id=\"zero_click_wrapper\" class=\"zci-wrap\"></div><div id=\"vertical_wrapper\" class=\"verticals\"></div><div id=\"web_content_wrapper\" class=\"content-wrap \"><div class=\"serp__top-right  js-serp-top-right\"></div><div class=\"serp__bottom-right  js-serp-bottom-right\"><div class=\"js-feedback-btn-wrap\"></div></div><div class=\"cw\"><div id=\"links_wrapper\" class=\"serp__results js-serp-results\"><div class=\"results--main\"><div class=\"search-filters-wrap\"><div class=\"js-search-filters search-filters\"></div></div><noscript><meta http-equiv=\"refresh\" content=\"0;URL=/html?q=ramen\"><link href=\"/css/noscript.css\" rel=\"stylesheet\" type=\"text/css\"><div class=\"msg msg--noscript\"><p class=\"msg-title--noscript\">You are being redirected to the non-JavaScript site.</p>Click <a href=\"/html/?q=ramen\">here</a> if it doesn't happen automatically.</div></noscript><div id=\"message\" class=\"results--message\"></div><div class=\"ia-modules js-ia-modules\"></div><div id=\"ads\" class=\"results--ads results--ads--main is-hidden js-results-ads\"></div><div id=\"links\" class=\"results is-hidden js-results\"></div></div><div class=\"results--sidebar js-results-sidebar\"><div class=\"sidebar-modules js-sidebar-modules\"></div><div class=\"is-hidden js-sidebar-ads\"></div></div></div></div></div><div id=\"bottom_spacing2\"> </div></div><script type=\"text/javascript\"></script><script type=\"text/JavaScript\">function nrji() {nrj('/t.js?q=ramen&t=D&l=us-en&s=0&dl=en&ct=US&ss_mkt=us&p_ent=&ex=-1');DDG.search.adSource='dsu';nrj('/d.js?q=ramen&t=D&l=us-en&s=0&a=h_&dl=en&ct=US&ss_mkt=us&vqd=3-2495358492768631519045579927498153959-79951267394787688665837204955443138657&p_ent=&ex=-1&sp=0');DDH.wikipedia_fathead=DDH.wikipedia_fathead||{};DDH.wikipedia_fathead.meta={\"src_name\":\"Wikipedia\",\"designer\":null,\"live_date\":null,\"dev_milestone\":\"live\",\"js_callback_name\":\"wikipedia\",\"unsafe\":0,\"src_url\":null,\"src_domain\":\"en.wikipedia.org\",\"dev_date\":null,\"status\":\"live\",\"producer\":null,\"is_stackexchange\":null,\"attribution\":null,\"production_state\":\"online\",\"blockgroup\":null,\"description\":\"Wikipedia\",\"signal_from\":\"wikipedia_fathead\",\"maintainer\":{\"github\":\"duckduckgo\"},\"perl_module\":\"DDG::Fathead::Wikipedia\",\"repo\":\"fathead\",\"topic\":[\"productivity\"],\"tab\":\"About\",\"name\":\"Wikipedia\",\"id\":\"wikipedia_fathead\",\"example_query\":\"nikola tesla\",\"created_date\":null,\"src_id\":1,\"src_options\":{\"skip_image_name\":0,\"is_wikipedia\":1,\"is_fanon\":0,\"src_info\":\"\",\"skip_abstract\":0,\"skip_qr\":\"\",\"language\":\"en\",\"is_mediawiki\":1,\"source_skip\":\"\",\"skip_end\":\"0\",\"skip_icon\":0,\"skip_abstract_paren\":0,\"min_abstract_length\":\"20\",\"directory\":\"\"},\"developer\":[{\"type\":\"ddg\",\"url\":\"http://www.duckduckhack.com\",\"name\":\"DDG Team\"}]};;};DDG.ready(nrji, 1);</script><script src=\"/g2157.js\"></script></body></html>";
            append "<div class=\"footer\" style=\"display: block;\"><div class=\"footer__left\"><div class=\"footer_cards\"><a class=\"footer__card js-footer-card bg-clr--white\" href=\"https://duckduckgo.com/traffic/\" data-id=\"traffic\"><img class=\"footer__card__icon\" src=\"/assets/icons/traffic.svg\" alt=\"\" aria-hidden=\"true\"><h3 class=\"footer__card__title tx-clr--slate\">30 Billion Searches</h3><p class=\"footer__text\">We get a ton of searches, and all of them are anonymous.</p></a><a class=\"footer__card js-footer-card bg-clr--white\" href=\"https://duckduckgo.com/newsletter\" data-id=\"su\"><img class=\"footer__card__icon\" src=\"/assets/icons/newsletter.svg\" alt=\"\" aria-hidden=\"true\"><h3 class=\"footer__card__title tx-clr--slate\">Our Crash Course</h3><p class=\"footer__text\">Take our Privacy Crash Course and learn about online privacy.</p></a><a class=\"footer__card js-footer-card bg-clr--white\" href=\"https://duckduckgo.com/bang\" data-id=\"ba\"><img class=\"footer__card__icon\" src=\"/assets/icons/bangs.svg\" alt=\"\" aria-hidden=\"true\"><h3 class=\"footer__card__title tx-clr--slate\">Learn About Bangs</h3><p class=\"footer__text\">Discover shortcuts to go to search results on other sites.</p></a></div></div><div class=\"footer__right\"><div class=\"footer__column\"><h2 class=\"footer__title tx-clr--slate-light\">Stay Informed</h2><p class=\"footer__text\">We don't track you, but others do.</p><p class=\"footer__text\">Learn how to protect your privacy.</p><div class=\"footer__links\"><a href=\"https://spreadprivacy.com\" class=\"js-footer-link\" data-id=\"bl\"><img class=\"footer__social-icon\" src=\"/assets/icons/footer/globe.svg\" alt=\"\" aria-hidden=\"true\"></a><a href=\"https://twitter.com/duckduckgo\" class=\"js-footer-link\" data-id=\"tw\"><img class=\"footer__social-icon\" src=\"/assets/icons/footer/twr.svg\" alt=\"\" aria-hidden=\"true\"></a><a href=\"https://reddit.com/r/duckduckgo\" class=\"js-footer-link\" data-id=\"rd\"><img class=\"footer__social-icon\" src=\"/assets/icons/footer/reddit.svg\" alt=\"\" aria-hidden=\"true\"></a><a href=\"https://duckduckgo.com/newsletter\" class=\"js-footer-link\" data-id=\"nl\"><img class=\"footer__social-icon\" src=\"/assets/icons/footer/newsletter.svg\" alt=\"\" aria-hidden=\"true\"></a></div></div></div></div>";
            print;
        }
    }
}

http-stager {
server {
header "Cache-Control" "no-cache";
header "Content-Type" "text/html; charset=UTF-8";
header "Vary" "Accept-Encoding";
header "Server" "Apache-Coyote/1.1";
header "Connection" "close";
}
}
