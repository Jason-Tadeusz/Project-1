# Splunk Lab

## Objective

To demonstrate advanced cybersecurity skills and practical experience in threat detection, incident response, and security monitoring using Splunk.
Complete a series of structured challenges that simulate real-world cyber attack scenarios, including brute force attacks, staging server identification, and ransomware analysis.
Display problem-solving skills and the ability to follow investigative leads to their conclusion.

### Skills Learned

- Advanced understanding of SIEM concepts and practical application.
- Improved proficiency in analyzing and interpreting logs from varied sources.
- Enhanced understanding of SPL commands and queries.
- Strengthened critical thinking and problem-solving abilities in the field of cybersecurity.
- Apply threat hunting techniques to discover malicious tools, tactics and procedures within a dataset.

### Tools Used

- Splunk for log analysis.
- VirusTotal for open source intelligence gathering.

## Scenarios

Scenario 1 (APT)
We are given access to a Splunk interface with the relevant datasets to investigate these incidents In this scenario, reports of a graphic come in from your user community when they visit the Wayne Enterprises website, and some of the reports reference “P01s0n1vy.” P01s0n1vy is an APT group that has targeted Wayne Enterprises.

Scenario 2 (Ransomware):
In the second scenario, one of your users is greeted by an image on a Windows desktop that is claiming that files on the system have been encrypted and payment must be made to get the files back. It appears that a machine has been infected with Cerber ransomware at Wayne Enterprises and your goal is to investigate the ransomware with an eye towards reconstructing the attack.

### Scenario 1 (APT)

Question:
What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

The first step to answering these questions is to list the relevant information we know. Two pieces of information are relevant: The domain is “imreallynotbatman.com” and scanning is a very noticeable activity with a large volume of events. We need to look at traffic related to the domain, and can do so by using this query:

index=”botsv1" imreallynotbatman.com

We are now able to see if the search helps to narrow the likely IP suspects by looking at the source IP addresses.

![Screenshot 2024-05-27 152546](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/97ea4eac-77a3-45eb-bdb7-0e4713fcd22d)
Here we can see three IPs. Let’s start with the one with the highest count by using the following query: 
index="botsv1"  imreallynotbatman.com src_ip="40.80.148.42"

Looking at the event contents, we see that this address is using the Acunetix Web Vulnerability Scanner. This confirms our answer: 40.80.148.4

2What company created the web vulnerability scanner used by Po1s0n1vy? 
We found this answer when answering the previous question: Acunetix



4. What content management system is imreallynotbatman.com likely using?

A content management system (CMS) is used to create, manage, and modify content on a website. The CMS may be mentioned in a file path on the website, which could be enumerated in the URL. Let’s take a look at some unique URL values for imreallynotbatman.com.

We see that joomla is listed in multiple URL’s. Let’s look up what joomla is.

Joomla is a CMS, which is exactly what we are looking for, confirming our answer: Joomla






5. What is the name of the file that defaced the imreallynotbatman.com website? 

The web server has been compromised at this point and will be the source of the file download request. The request will likely be using the HTTP protocol, which can further narrow our search.

index=botsv1 src_ip=192.168.250.70 sourcetype="stream:http"

We are given only 8 events from this search, which makes things easier. We can look at the details of these packets and find that one of the source headers is quite conspicuous.

Answer: poisonivy-is-coming-for-you-batman.jpeg

6. This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?
The FQDN from which the file was downloaded can be seen where we found our previous answer.
Answer: prankglassinebracket.jumpingcrab.com

7. What IP address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

We found two IPs that are malicious. 23.22.63.114 is where the malicious file was downloaded from and 40.80.148.42 was the source of the scanning. We can find more information on these IPs using Virustotal.

We found on virus total that 23.22.63.114 is associated with malicious domains.
Answer:23.22.63.114


8. What IP address is likely attempting a brute force password attack against imreallynotbatman.com?
Brute force password attacks will have the webserver as the destination IP and HTTP POST method. The following will thus be our query:

index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http"

The password attack will be evident in the form data, which often displays credentials, so lets take a look at those values.

As you can see, there are many unique values, so we will have them displayed in a way that makes it easier to investigate by using the following query:

index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http"| stats count by src_ip, form_data

Here we can see that the IP 23.22.63.114 is attempting to brute force using many different passwords.
Answer:23.22.63.114


10. What is the name of the executable uploaded by Po1s0n1vy?

We know that files are uploaded using the HTTP POST method and executables usually end in .exe. We will use the following query:

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST *exe

This gives us three events to look into. We can see two filenames listed in the field, one of which is an executable and also our answer.

Answer: 3791.exe

11. What is the MD5 hash of the executable uploaded?
First we need to find which log source contains the hash values of files to narrow our search.

Query:index=botsv1 (Sampling to speed up the process)

From here we can search for a fieldname containing hash values. When including only events that include these fields, we find that Windows Sysmon is the only sourcetype that will give us the hash value of files.

index=botsv1 3791.exe sourcetype=”XmlWinEventLog:Microsoft-Windows-Sysmon/Operational” 3791.exe

We have narrowed the search which helps us to pick out the field that will lead us to the answer. We look at the command line field, which contains 3791.exe. Adding this to our query gives us one event with the hash value.

Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0

12. GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

The initial attack infrastructure involves the IP address 23.22.63.114. We previously employed VirusTotal to find the domains linked to 23.22.63.114. Scrolling further down the page reveals three malware files in the "Communicating files" section.

The file MirandaTateScreensaver.scr.exe is the most likely used in phishing attacks. Let's click on it and find the details, which include the SHA256 Hash.

Answer: 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8

13. What special hex code is associated with the customized malware discussed in question 11?
Still using VirusTotal, our investigation leads us to the community tab, where a hex code associated with the malware is contained.
Answer: 53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21

What was the first brute force password used?

We previously found the brute force attempt and can continue that investigation to find the answer. To find the first attempt, we must sort the results by time. It is also helpful to put the results in a table to help visualize the data.

index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http" src_ip=23.22.63.114 | sort _time | table  _time src_ip form_data
Here we can see that the entries are chronologically sorted and that the first password attempt is 12345678.

Answer:12345678

One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

This question asks us to pick out a specific phrase with certain parameters. To do so we need to identify Coldplay songs with six-character titles. Here is a list that will include some of the songs that qualify: Violet, Sparks, Square, Yellow, Shiver, Clocks, Always, Ghosts, and Church.
We'll then attempt to match any captured passwords with these song titles.
(?i) makes the pattern case-insensitive. (?<password>[a-zA-Z]{6})` captures a six-letter password using `[a-zA-Z]{6}`, which matches any six consecutive letters, regardless of case.
Once the password is captured, the "search" command filters for passwords that match any of the Coldplay songs listed. The "IN" operator checks if the "password" field matches any song title in the list. We will then get the password in the table.

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST 
| rex field=form_data "(?i)passwd=(?<password>[a-zA-Z]{6})"
| search password IN (Violet, Sparks, Square, Yellow, Shiver, Clocks, Always, Ghosts, Church)
| table password

Answer:Yellow


