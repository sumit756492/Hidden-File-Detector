# Hidden-File-Detector
Legacy-compatible security tool for detecting hidden files and encoded content. Supports Python 2.7-3.x across Windows/Linux/macOS including older systems (XP, CentOS 6, OS X 10.6). Decodes Base64, Hex, ROT13, Caesar cipher. Auto-scan mode for CTF competitions and security audits.

# Smart scanning - checks common hiding spots
python hidden_file_detector.py auto

# Audit a server you manage
python hidden_file_detector.py /var/www/
python hidden_file_detector.py /home/
