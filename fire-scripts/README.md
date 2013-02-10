fire-scripts
=

The "print line" has to be one of the oldest debugging and development techniques taught in introductory CS classes.  With the Bro Network Programming language developers are learning- protocols and protocol analyzers are complex.  Even on seeming "simple" protocols the devil is in the details and edge cases of the RFC.

These Bro scripts are intended to aid in the initial development and understanding of when Bro events are firing off as traffic drives the Bro Network Programming language forward through the state of each protocol.  These scripts have little productioin value however will help to the user to understand the order, frequency and information available to the user as each event fires.

### Naming Convention
We are using the following naming convention for each protocol script:

**NAME-fire.bro:** 
As each event fires print do a printline to the screen.

**NAME-fire-count.bro:** Upon the completion of Bro and the firing of the [bro_done](http://www.bro-ids.org/documentation/scripts/base/event.bif.html#id-bro_done) event show some simple metrics as to the frequency of each event.

**NAME-fire-detail:** Warning, verbose. Print the raw variables out with some basic formating for each variable.

**NAME-fire-detail-raw:** Warning, verbose. Just print each of the raw variable out to the screen as each event fires.

**capture-events.bro:** Warning, very verbose. Capture all events and print their contents in one file.  

### Usage

````
wopr$ bro -r sample-ssl-tls.pcap ./fire-scrirpts/ssl-tls-fire.bro
````

**Output**

    wopr$ bro -r sample-http.pcap ./fire-scripts/ssl-tls-fire.bro
    event ssl_client_hello
    event ssl_server_hello
    event x509_certificate
    event ssl_established
    event ssl_client_hello
    event ssl_server_hello
    event ssl_established
    ----------------------------------
    Bro is done

````
wopr$ bro -r sample-ssl-tls.pcap ./fire-scripts/capture-events.bro
wopr$ bro -x events.bst
````

**Output**

    wopr$ bro -r sample-http.pcap ./fire-scripts/capture-events.bro
    Date: Sun Feb 10 12:16:44 2013
    Event [1360464997.544257] new_connection([id=[orig_h=192.168.4.137, orig_p=43849/tcp, resp_h=74.125.228.21, resp_p=443/tcp], orig=[size=0, state=0, num_pkts=0, num_bytes_ip=0, flow_label=0], resp=[size=0, state=0, num_pkts=0, num_bytes_ip=0, flow_label=0], start_time=1360464997.544257, duration=0.0, service={}, addl="", hot=0, history="", uid="cq18EfUt8ff", tunnel=<uninitialized>, dpd=<uninitialized>, conn=<uninitialized>, extract_orig=F, extract_resp=F, dns=<uninitialized>, dns_state=<uninitialized>, ftp=<uninitialized>, http=<uninitialized>, http_state=<uninitialized>, irc=<uninitialized>, smtp=<uninitialized>, smtp_state=<uninitialized>, socks=<uninitialized>, ssh=<uninitialized>, ssl=<uninitialized>, syslog=<uninitialized>])
    Event [1360464997.917501] new_connection([id=[orig_h=192.168.4.137, orig_p=33093/tcp, resp_h=74.125.228.97, resp_p=443/tcp], orig=[size=0, state=0, num_pkts=0, num_bytes_ip=0, flow_label=0], resp=[size=0, state=0, num_pkts=0, num_bytes_ip=0, flow_label=0], start_time=1360464997.917501, duration=0.0, service={}, addl="", hot=0, history="", uid="iaqAdIFadVd", tunnel=<uninitialized>, dpd=<uninitialized>, conn=<uninitialized>, extract_orig=F, extract_resp=F, dns=<uninitialized>, dns_state=<uninitialized>, ftp=<uninitialized>, http=<uninitialized>, http_state=<uninitialized>, irc=<uninitialized>, smtp=<uninitialized>, smtp_state=<uninitialized>, socks=<uninitialized>, ssh=<uninitialized>, ssl=<uninitialized>, syslog=<uninitialized>])
    Event [1360464998.035013] connection_established([id=[orig_h=192.168.4.137, orig_p=33093/tcp, resp_h=74.125.228.97, resp_p=443/tcp], orig=[size=0, state=4, num_pkts=1, num_bytes_ip=60, flow_label=0], resp=[size=0, state=4, num_pkts=0, num_bytes_ip=0, flow_label=0], start_time=1360464997.917501, duration=0.117512, service={}, addl="", hot=0, history="Sh", uid="iaqAdIFadVd", tunnel=<uninitialized>, dpd=<uninitialized>, conn=<uninitialized>, extract_orig=F, extract_resp=F, dns=<uninitialized>, dns_state=<uninitialized>, ftp=<uninitialized>, http=<uninitialized>, http_state=<uninitialized>, irc=<uninitialized>, smtp=<uninitialized>, smtp_state=<uninitialized>, socks=<uninitialized>, ssh=<uninitialized>, ssl=<uninitialized>, syslog=<uninitialized>])
 


For a detailed and authoritative description of each Bro script please see:

[event.bif](http://www.bro-ids.org/documentation/scripts/base/event.bif.html)

-or-

$BROHOME$/bro/share/bro/base/event.bif.bro

This should be considered a work-in-progress; for the latest version please see [my git-hub account](https://github.com/LiamRandall).  I will begin with the most common protocols first; eventually I would like to add a series of scripts that help the user quickly identify abnormalities in the pcap samples.  The more programming I do in the Bro Network Programming language the more great ideas I have- like many others in this small community I know the future is full of possiblity and that Bro-IDS is only the first great program to be written in the Bro Network Programming Lanuage.  I sincerely hope these assist you to get up to speed quickly.

Sincerely,

Liam Randall  [@Hectaman](https://twitter.com/hectaman)


**Key:**
- [ ] Not yet started
- [-] Under development
- [X] Complete


**Current Status:**

- [ ] http
- - [X] http-fire.bro
- - [ ] http-fire-count.bro
- - [ ] http-fire-detail.bro
- - [-] http-fire-detail-raw.bro
- [ ] dns
- - [X] dns-fire.bro
- - [ ] dns-fire-count.bro
- - [ ] dns-fire-detail.bro
- - [ ] dns-fire-detail-raw.bro
- [ ] ssl-tls
- - [X] ssl-tls-fire.bro
- - [X] ssl-tls-fire-count.bro
- - [ ] ssl-tls-fire-detail.bro
- - [ ] ssl-tls-fire-detail-raw.bro

