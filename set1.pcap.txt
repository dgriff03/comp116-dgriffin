set1.pcap
----------
1. 1503 packets in the set
2. FTP/FTP-data was used to move files from PC to Server
3. The information is passed in the clear, as such the file can be recreated.
4. SFTP is the secure version of the FTP protocol
5. The server IP is 67.23.79.113
6. username: ihackpineapples password: rockyou1
7. 4 files were passed, 3 jpg, 1 txt
8.  BjN-01hCAAAZbiq.jpg
	BvgT9p2IQAEEoHu.jpg
	BvzjaN-IQAA3XG7.jpg
	smash.txt
9. The files are in the repo with the correct names

set2.pcap
----------
10. There are 77882 packets
11. 1
12. I used grep to search for PASS in the pcap file using ettercap to convert 
	to text.
13. POP protocol to http://mail.si-sv3231.com/
14. The username-password pair was legitimate.
15. The plain text username-password pair was found to be legitamate as when 
	following the interaction with Wireshark the server returned Ok password
	as well as mailing information that would be behind the login wall.
16. Ensure that all pop connections require SSL such that the file transfer is
	not plain text.
