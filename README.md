🔍 Lz7Tools - OSINT and Network Scanner Menu

An interactive menu with simple yet powerful tools for pentesters, forensic analysts, and cybersecurity enthusiasts.


---

📦 Features

✅ Website Vulnerability Scanner (XSS, SQLi, LFI, CMD)
✅ IP Scanner (via ip-api)
✅ Port Scanner (TCP from 1 to 1024)
✅ Username Tracker (30+ platforms)
✅ Email Lookup (Gravatar, leaks, social networks)
✅ Phone Lookup (Truecaller, Google, social networks)
✅ EXIF Reader (image metadata and GPS info)
✅ Google Dork Generator
✅ IP Geolocation (with Google Maps link)


---

💻 Installation

📱 Termux (Android)

pkg update && pkg upgrade -y
pkg install python git -y
pip install -r requirements.txt
git clone https://github.com/lz7-D3v/Lz7Tools.git
cd Lz7Tools
python menu.py

🐧 Kali Linux / Ubuntu / Debian / Parrot OS

sudo apt update && sudo apt install python3 python3-pip git -y
pip3 install -r requirements.txt
git clone https://github.com/lz7-D3v/Lz7Tools.git
cd Lz7Tools
python3 menu.py

🪟 Windows

1. Install Python from the official website


2. Install the dependencies:



pip install -r requirements.txt

3. Download the repository:



git clone https://github.com/lz7-D3v/Lz7Tools.git
cd Lz7Tools
python menu.py


---

🧰 Dependencies

The libraries used are:

requests

colorama

Pillow (for EXIF reading)


Install them with:

pip install -r requirements.txt


---

📘 How to Use

Run menu.py and explore the menu options:

[1] Network Scanner → IP, port, and vulnerability scanner
[2] OSINT → username, email, phone tracking
[3] Utilities → EXIF reader, dorks, IP geolocation


---

⚠️ Legal Disclaimer

> This tool is intended for educational and ethical purposes only.
The author is not responsible for any misuse.




---

✨ Author

Lz7.D3v
Telegram: @Lz7D3v
