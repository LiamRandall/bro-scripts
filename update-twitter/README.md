 update-twitter.bro
=========


update-twitter.bro is a simple little applicaiton to demonstrate driving other applications based on and incorporating the output of Bro-IDS.  With this demonstration Twitter could easily be replaced with something such as Google Caprica to dynamically manage your ASA, integrated into your NAC, or what ever sort of a mashup you can envision.

The twitter command line client is based on the demo, here:
    http://talkfast.org/2010/05/31/twitter-from-the-command-line-in-python-using-oauth/
    
The two python files you will need to use these are prefixed with .skel the [projects home on github](https://github.com/LiamRandall/bro-scripts/tree/master/update-twitter).

**Note**

The default OATH client is presently limited to 350 queries updates per hour.  For more information please see the [Twitter OATH API](https://dev.twitter.com/docs/auth/oauth).


**Basic Instruction**

To implement these scripts using SecurityOnion and Bro 2.1 you will need to install some pre-requisites:

    sudo apt-get install python python-pip
    sudo pip install tweepy

Please contact [Liam Randall](liam.randall@gmail.com) with any comments or questions.  
Twitter/IRC: @Hectaman
Freenode: #Bro
