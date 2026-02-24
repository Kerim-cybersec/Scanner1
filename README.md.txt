
_____                                         __ 
 / ____|                                       /_ |
| (___   ___ __ _ _ __  _ __   ___ _ __         | |
 \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|        | |
 ____) | (_| (_| | | | | | | |  __/ |           | |
|_____/ \___\__,_|_| |_|_| |_|\___|_|           |_|


# Custom Port Scanner & Vuln Tool
This is a project I built as part of my Cybersecurity Apprenticeship. It's a Python script that hunts for open ports and flags potential security risks.

## Why did I make this
I wanted to move beyond just using tools like Nmap and actually understand how a TCP connection works. Building this helped me develop my python skills as well

## What does this scan aim to do
* Fast Scanning: It uses 100 threads to check 10,000 ports in about 30-40 seconds
* Risk Flagging: It doesn't just find ports, it also tells you if they are high-risk (like Telnet or unencrypted FTP)
* Progress Bar:  I added a visual bar so you can see exactly how far through the scan it is

## How to use it
1. Make sure you have Python installed lol
2. Download `scanner1.py`.
3. Open your terminal in that folder and run: 
   `python scanner1.py`

## A quick warning
I built this for my own learning and for ethical testing. Please do not use this tool scanning networks you don't own. That's a quick way to get into trouble with your ISP :D 