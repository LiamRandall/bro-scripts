fire-scripts
=

The "print line" has to be one of the oldest debugging and development techniques taught in introductory CS classes.  With the Bro Network Programming language developers are learning- protocols and protocol analyzers are complex.  Even on seeming "simple" protocols the devil is in the details and edge cases of the RFC.

These Bro scripts are intended to aid in the initial development and understanding of when Bro events are firing off as traffic drives the Bro Network Programming language forward through the state of each protocol.  These scripts have little productioin value however will help to the user to understand the order, frequency and information available to the user as each event fires.

We are using the following naming convention for each protocol script:

**NAME-fire.bro:** 
As each event fires print do a printline to the screen.

**NAME-fire-count.bro:** Upon the completion of Bro and the firing of the [bro_done](http://www.bro-ids.org/documentation/scripts/base/event.bif.html#id-bro_done) event show some simple metrics as to the frequency of each event.

**NAME-fire-detail:** Warning, verbose. Print the raw variables out with some basic formating for each variable.

**NAME-fire-detail-raw:** Warning verbose. Just print each of the raw variable out to the screen as each event fires.

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
- - [ ] ssl-tls-fire.bro
- - [ ] ssl-tls-fire-count.bro
- - [ ] ssl-tls-fire-detail.bro
- - [ ] ssl-tls-fire-detail-raw.bro

