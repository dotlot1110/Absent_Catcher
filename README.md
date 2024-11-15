# Absent_Catcher

# Introduction
The purpose of this project is to develop an attendance verification system to ensure the 
physical attendance. This project aims to make the system to confirm whether students are 
present in the vicinity of the classroom when they attempt to check in for attendance by 
leveraging the MAC addresses of Wi-Fi packets.

# Implementation
The system will be developed using Python and will consist of two main components: the client 
(student) application and the server. The client application will utilize the Scapy library in Python 
for packet capturing, while the server will implement an API using Flask to facilitate smooth 
communication between the client and server components. Additionally, a database will be 
created to store valid AP MAC addresses for classrooms. 

STEP 1: When the client attempts to check in for the attendance, the client will capture Wi-Fi 
packets and send them with the student’s identification (ID) to the server. 
STEP 2: The server receives the packet data and extracts MAC address from the Wi-Fi packets. 
STEP 3: The server compares the extracted MAC address with a pre-stored list of valid MAC 
addresses associated with the classroom's APs. 
STEP 4: Based on comparison, the server will either approve or deny the attendance request. 
