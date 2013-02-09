detect-bruteforce
===========

**detect-bruteforce.bro**

This version is the cluster safe version of the script compatible with the metrics framework as released in Bro 2.1.  The script automatically detects and monitors the STATUS_CODE returned by responder (server), by site (url), by originator (client).  The notices may be used to alert of potential suspicious activity, misconfigured, or malfunctioning servers.



**http-status-codes-with-client.bro**

This version is not cluster safe; the intent of this script is intended as a training and example script to demonstrate the bro developemnt process.  A version of this script was taught by Liam Randall during [Flocon 2013](http://www.cert.org/flocon/).
