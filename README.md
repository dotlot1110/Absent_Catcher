# Absent_Catcher

### Introduction
&ensp;The purpose of this project is to develop an attendance verification system which ensures the physical attendance of the students.
It aims to implement the system that confirms whether the students are really present in the the classroom during their attendance check,
using the MAC addresses of Wi-Fi access points located in each classroom. 

### Implementation
&ensp;The system will be developed using Python and consist of two main components: the client application for the students and the server.
The client application will utilize the Scapy library in Python to capture the packets.
Then the server will be implemented with proper APIs for smooth communication between the client and the server.
Additionally, a database will be created to store valid AP MAC addresses of each classroom. 

STEP 1: When a client attempts to check the attendance, the application captures Wi-Fi packets and sends them with the student’s identification number to the server. 

STEP 2: The server receives the packet data which consists of extracted MAC addresses from the Wi-Fi packets. 

STEP 3: The server compares the extracted MAC address with a pre-stored list of valid MAC addresses associated with the classroom's Wi-Fi access points. 

STEP 4: Based on the comparison, the server approves or denies the attendance request and sends the result to the client.
