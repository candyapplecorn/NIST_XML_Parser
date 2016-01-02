# NIST_XML_Parser
Program which makes a double column list of of NIST vulnerabilities

Someone wanted a two column list made from the XML files on the NIST vulnerability page, in order to easily plug the data into Excel.
First column is the CVE identifier, second column is the score. 
About 1% of CVE's don't have scores.

The perl program can be run without the node server.
The node server simply allows the program to be run over the internet, and for its output to be downloaded too.
My previous solution to the problem of getting the two column list was to make a shell script, however it stopped working. This time I don't have to worry about a script not working on a client's machine, since this program will always be reachable and work on my server.

**Note on Efficiency:**
*This program isn't.* I added a cooldown to index.js which keeps people from re-downloading all the NIST xml files more than once every five minutes, however this doesn't meet NIST's standards at all. NIST provides a "modified" XML feed which contains a list of all CVE's that have been modified in the last two hours. This list changes every two hours, with entries rotating in and out every 8 days from when they were entered into "modified.xml". The correct approach is to check "modified.xml" every two hours and then check that against a database of all the nvdcve entries, updating what's new or changed. However this would require me to write a program which checks the "modified.xml" feed every two hours. That would require me to learn how to write a daemon, or some other kind of always-on background program, and since this whole thing is just for someone to use once a week, I did things inefficiently and wastefully (*on second thought, index.js is always on, so that could just pull "modified.xml" every two hours. Doh!*). But hey, it works, and it **saves someone about 3 hours every week**.

*pw.ini's contents might be "username password"*
