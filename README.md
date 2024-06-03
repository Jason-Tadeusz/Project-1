# Splunk Lab

## Objective

To demonstrate advanced cybersecurity skills and practical experience in threat detection, incident response, and security monitoring using Splunk.
Complete a series of structured challenges that simulate real-world cyber attack scenarios, including brute force attacks, staging server identification, and ransomware analysis.
Display problem-solving skills and the ability to follow investigative leads to their conclusion.

### Skills

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

### Question 1: What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

The first step to answering these questions is to list the relevant information we know. Two pieces of information are relevant: The domain is “imreallynotbatman.com” and scanning is a very noticeable activity with a large volume of events. We need to look at traffic related to the domain, and can do so by using this query:

index=”botsv1" imreallynotbatman.com

We are now able to see if the search helps to narrow the likely IP suspects by looking at the source IP addresses.

![Screenshot 2024-05-27 152546](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/97ea4eac-77a3-45eb-bdb7-0e4713fcd22d)

Here we can see three IPs. Let’s start with the one with the highest count by using the following query: 

index="botsv1"  imreallynotbatman.com src_ip="40.80.148.42"

![Screenshot 2024-05-28 095338](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/7a79d4cf-fa89-4e4c-8799-729f8045d08e)

Looking at the event contents, we see that this address is using the Acunetix Web Vulnerability Scanner. This confirms our answer: 40.80.148.4

### Question 2: What company created the web vulnerability scanner used by Po1s0n1vy? 

We found this answer when answering the previous question: Acunetix

### Question 3: What content management system is imreallynotbatman.com likely using?

A content management system (CMS) is used to create, manage, and modify content on a website. The CMS may be mentioned in a file path on the website, which could be enumerated in the URL. Let’s take a look at some unique URL values for imreallynotbatman.com.

![Screenshot 2024-05-28 101923](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/4858c40d-6e52-4878-9aa8-38f9dc24657a)

We see that joomla is listed in multiple high freqency URL’s. Let’s look up what joomla is.

![Screenshot 2024-05-28 102214](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/8ef1cbaa-01ac-4553-b07f-67a0f9e70367)

Joomla is a CMS, which is exactly what we are looking for, confirming our answer: Joomla

### Question 4: What is the name of the file that defaced the imreallynotbatman.com website? 

The web server has been compromised at this point and will be the source of the file download request. The request will likely be using the HTTP protocol, which can further narrow our search.

index=botsv1 src_ip=192.168.250.70 sourcetype="stream:http"

![Screenshot 2024-05-28 105727](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/86565819-793a-4aa1-abe8-4541e0d8d95a)

We are given only 8 events from this search, which makes things easier. We can look at the details of these packets and find that one of the source headers is quite conspicuous.

![Screenshot 2024-05-28 105943](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/3bbc2d62-9f9d-43ed-9ad0-99b119d4dd4b)

Answer: poisonivy-is-coming-for-you-batman.jpeg

### Question 6: This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

The FQDN from which the file was downloaded can be seen where we found our previous answer.

Answer: prankglassinebracket.jumpingcrab.com

### Question 7: What IP address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

We found two IPs that are malicious. 23.22.63.114 is where the malicious file was downloaded from and 40.80.148.42 was the source of the scanning. We can find more information on these IPs using Virustotal.

![Screenshot 2024-05-28 112238](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/20a568ce-da8f-4c1a-bf3a-6207141e3b9e)

We found on virus total that 23.22.63.114 is associated with malicious domains.

Answer:23.22.63.114

### Question 8: What IP address is likely attempting a brute force password attack against imreallynotbatman.com?

Brute force password attacks will have the webserver as the destination IP and use HTTP POST method. The following will thus be our query:

index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http"

The password attack will be evident in the form data, which often displays credentials, so lets take a look at those values.

![Screenshot 2024-05-28 113134](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/ce80baf8-d525-4bb1-8550-dc466148a8c5)


As you can see, there are many unique values, so we will have them displayed in a way that makes it easier to investigate by using the following query:

index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http"| stats count by src_ip, form_data

![Screenshot 2024-05-28 113856](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/9ed0c3d8-90f4-4aaf-a212-3aa52d4b2340)

Here we can see that the IP 23.22.63.114 is attempting to brute force using many different passwords.

Answer:23.22.63.114

### Question 9: What is the name of the executable uploaded by Po1s0n1vy?

We know that files are uploaded using the HTTP POST method and executables usually end in .exe. We will use the following query:

index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST *exe

![Screenshot 2024-05-28 114448](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/6e258891-160c-43b5-8423-f412673ba79d)

This gives us three events to look into. We can see two filenames listed in the field, one of which is an executable and also our answer.

![Screenshot 2024-05-28 115015](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/927d79d5-6452-4131-9058-24f6f8449eb7)

Answer: 3791.exe

### Question 10: What is the MD5 hash of the executable uploaded?

First we need to find which log source contains the hash values of files to narrow our search.

Query:index=botsv1 (Sampling to speed up the process)

![Screenshot 2024-05-28 120804](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/4e987afb-f3ac-4fe1-97f4-a6a7f7769725)

From here we can search for a fieldname containing hash values. When including only events that include these fields, we find that Windows Sysmon is the only sourcetype that will give us the hash value of files.

index=botsv1 3791.exe sourcetype=”XmlWinEventLog:Microsoft-Windows-Sysmon/Operational”

![Screenshot 2024-05-28 121121](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/f8f72fd2-48c0-4919-a68c-aec4e736e1f7)

We have narrowed the search which helps us to pick out a hash field that will lead us to the answer. We look at the command line field, from which 3791.exe was executed. Adding this to our query gives us one event with the hash value.

index=botsv1 sourcetype=”XmlWinEventLog:Microsoft-Windows-Sysmon/Operational” 3791.exe CommandLine="3791.exe"

![Screenshot 2024-05-28 123154](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/b7f7ab8f-3432-49d6-a7ea-ebd118efd93c)

Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0

### Question 12. GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

The initial attack infrastructure involves the IP address 23.22.63.114. We previously employed VirusTotal to find the domains linked to 23.22.63.114. Scrolling further down the page reveals three malware files in the "Communicating files" section.

The file MirandaTateScreensaver.scr.exe is the most likely used in phishing attacks. Let's click on it and find the details, which include the SHA256 Hash.

Answer: 9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8

### Question 13. What special hex code is associated with the customized malware discussed in question 11?

Still using VirusTotal, our investigation leads us to the community tab, where a hex code associated with the malware is contained.
Answer: 53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21

### Question 14. What was the first brute force password used?

We previously found the brute force attempt and can continue that investigation to find the answer. To find the first attempt, we must sort the results by time. It is also helpful to put the results in a table to help visualize the data.

index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http" src_ip=23.22.63.114 | sort _time | table  _time src_ip form_data

![Screenshot 2024-05-31 144115](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/b05d2981-728a-4f39-9cff-8de9674aa7e7)

Here we can see that the entries are chronologically sorted and that the first password attempt is 12345678.

Answer:12345678


### Question 15. One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

This question asks us to pick out a specific phrase with certain parameters. The password must have a length of six characters, all of which will be letters. The syntax of the field is such that "passwd=” precedes the six letter password. We can use this to narrow our search to just six letter password strings.

index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http" src_ip=23.22.63.114 | regex form_data="passwd=[A-Za-z]{6}"

![Screenshot 2024-05-31 152120](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/200bf4b1-fee9-439a-95f1-a6c85d697f23)

Here we see that we still have 315 events to look through. We need to think what other parameters could be used to narrow our search. We can look up a list of coldplay songs and find ones with six letters in their name and use them in our query.

index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http" src_ip=23.22.63.114 | regex form_data="passwd=clocks"

![Screenshot 2024-05-31 150420](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/a299c5ee-e8a7-45ea-af19-9e27de9db9af)

Unfortunately, clocks wasn’t the song name we were looking for. Lets try another.

index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http" src_ip=23.22.63.114 | regex form_data="passwd=yellow"

![Screenshot 2024-06-01 204603](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/73197862-c978-4236-8504-8bd399606964)

We have a match!

Answer:Yellow

### Question 16. What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

Let’s look at some sign-ons from sources that aren’t attempting to brute force. 
index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http" | regex form_data="passwd=*"

![Screenshot 2024-05-31 152120](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/db567090-b714-4c69-a19b-f775cafd962a)

It looks like there is only one log on attempt from another source, so lets take a look at that one.

![Screenshot 2024-06-01 144513](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/1ac0ae55-abc7-4893-9cf0-1bb8ce98f393)

This login attempt used the password “batman” to log on.

Answer: Batman

### Question 17. What was the average password length used in the password brute forcing attempt?

To answer this question, we must extract the passwords from “form_data” using the common “rex”. Once we have the passwords extracted, we will need to evaluate the length of characters of the passwords and put it into a new field. We will use the following query:

index=botsv1 dest_ip=192.168.250.70 http_method=POST sourcetype="stream:http" src_ip=23.22.63.114 |rex field=form_data "passwd=(?<password>\w+)" | eval length=len(password)

![Screenshot 2024-06-01 150756](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/e4cb4f6a-0ade-444a-b200-b013451e385c)

Here is the field extracted with relevant statistics calculated and displayed for us. It gives us the average value of the length field, corresponding to the number of characters in the passwords.

Answer: 6

### Question 18. How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login?

To answer this, we will narrow the query so that only events in which the correct password “batman” was used are displayed.

![Screenshot 2024-06-01 151618](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/9aff96a1-d7c6-4fea-858d-b396912001a6)

Now that we have the only two events that are relevant, we will look at their times and calculate the time in seconds.

![Screenshot 2024-06-01 152429](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/e1416feb-f439-4709-8a2e-70563d24d6f7)

Answer=92.17

### Question 19. How many unique passwords were attempted in the brute force attempt?

Since we have a query that extracts the passwords, we can simply find the count of the passwords.

![Screenshot 2024-06-01 160448](https://github.com/Jason-Tadeusz/Splunk-Lab/assets/155782613/4c4d473f-2ae5-4403-89c9-f0ebc26c0900)

There are 412 unique password values listed in the count statistic.

Answer: 412


