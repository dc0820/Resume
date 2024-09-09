# Daniel Wayne Cook - Resume

## Contact Information
**Location:** San Antonio, Texas  
**Phone:** (210) 990-9940  
**Email:** [danielwcook5@gmail.com](mailto:danielwcook5@gmail.com)  
**LinkedIn:** [linkedin.com/in/danielwaynecook](https://www.linkedin.com/in/danielwaynecook/)  
**Website:** [danielcook.org](https://www.danielcook.org) | [danielcookjs.org](https://www.danielcookjs.org)

---

## Summary
Recent graduate with a Bachelor of Business Administration in Cyber Security from The University of Texas at San Antonio. Skilled in cybersecurity frameworks, penetration testing, and malware analysis. Proficient in programming and DevSecOps practices, with a strong foundation in secure network architecture and application security. Eager to apply my technical expertise to protect and secure digital assets in real-world IT environments.

---

## Education
**The University of Texas at San Antonio**  
- **Degree:** Bachelor of Business Administration, Major in Cyber Security  
- **Graduated:** May 2024  
- **GPA:** 3.57 / 4.0  

### Certifications:
- **CompTIA Security+** (2023)  
- **Google Cybersecurity Professional Certificate** (2023)

---

## Technical Skills

### Programming Languages
- Python, Java, JavaScript, TypeScript

### Web Development
- React, CSS

### Cybersecurity
- **Malware Analysis:** x32dbg, YARA, PEStudio, bstrings, Wireshark  
- **Penetration Testing:** Kali Linux, Metasploit, Nmap  
- **Application Security:** SAST, DAST, SCA, API Security

### DevOps and Automation
- **CI/CD Practices**  
- **Tools:** Jenkins, Docker, Kubernetes

### Other
- Vulnerability Management  
- Business Continuity and Disaster Recovery  
- Technical Architecture  
- **Security Frameworks:** NIST CSF, MITRE ATT&CK Framework  
- **SIEM Technologies**  
- **Microsoft Office Suite (Advanced):** Excel, Access, PowerPoint  
- Data Analysis, Database Management

---

## Soft Skills
- Communication (especially technical communication)  
- Leadership  
- Mentoring  
- Teamwork  
- Adaptability  
- Continuous learning

---

## Projects

### Capstone Project: Malware Analysis and Data Leak Prevention
*Final Project - Malware Analysis (Spring 2024)*  
- Utilized YARA rules to detect malicious IP activity and analyzed compromised files, including `winmedia.exe` and `winpass.exe`, using tools like PEStudio and bstrings to extract URLs and other relevant information.
- Reverse-engineered packed malware using PEiD and x32dbg to discover how the malware operated, identifying its kill-switch mechanism, "unlock."
- Decrypted obfuscated files using xor.exe, successfully uncovering the countdown password "unlock" and preventing a simulated data leak scenario.
- Demonstrated expertise in malware detection, reverse engineering, and real-time incident response under high-pressure situations.
- Developed and presented detailed incident response plans to mitigate potential real-world data leak threats.

### Malware Analysis Projects
- **PoisonIvy Malware Analysis**  
  *Course Project - Intrusion Detection & Incident Response (Spring 2024)*  
  - Conducted in-depth analysis of a compromised FTP server infected with the PoisonIvy backdoor trojan using tools like nmap, netcat, and tasklist.
  - Uncovered persistence mechanisms in the System32 folder, where `PoisonIvy.exe` created registry entries and injected itself into `explorer.exe` to maintain control of the compromised system.
  - Traced network communication with a remote control server and implemented countermeasures to mitigate unauthorized access.

- **Virus.exe Malware Analysis (Greg Analysis)**  
  *Course Project - Malware Analysis (Spring 2024)*  
  - Performed an in-depth analysis of `virus.exe` using tools such as capa and bstrings, investigating file creation and deletion behaviors.
  - Detected malware attempts to connect to Google Public DNS and identified deletion of `Winsystems64.exe` after failure to establish a connection.
  - Demonstrated advanced malware behavior analysis, providing insights into the malware’s operational flow and server communication attempts.

- **Malware Analysis of rip.exe**  
  *Course Project - Malware Analysis Class (Fall 2023)*  
  - Utilized x32dbg to analyze and modify the behavior of the `rip.exe` malware executable, identifying its "sleep" function.
  - Modified its binary expression using HxD to bypass the delay mechanism, creating a functioning, altered version, `rip2.exe`, that remained "awake."

- **OnyxCrew Malware Analysis**  
  *Course Project - Malware Analysis (Spring 2024)*  
  - Analyzed `OnyxCrew` malware using tools such as PEiD and bstrings to unpack the malicious executable `reserver.exe.vxe` and examine its persistence mechanisms.
  - Discovered an embedded URL linking to a Bitcoin wallet via a QR code, demonstrating how the malware was monetized.
  - Analyzed registry keys and network paths to fully understand the malware’s operational impact on system security.

---

### Penetration Testing and Forensics
- **Memory Forensics and Intrusion Detection**  
  *Course Project - Intrusion Detection & Incident Response (Fall 2022)*  
  - Conducted an in-depth memory forensic analysis of `KobayashiMaru.vmem` using Volatility, uncovering malware like `poisonivy.exe` and `Hacker Defender` rootkits.
  - Mapped system DLL manipulations, including `kernel32.dll`, which helped identify an ongoing cyber attack.

- **Exploring SimSpace Cyber Range with Penetration Testing Tools**  
  *Course Project - Cyber Range Lab (Spring 2023)*  
  - Conducted network scanning using nmap to identify live hosts and open ports in a simulated cyber range environment.
  - Utilized Medusa, SQLmap, and Aircrack-ng to test authentication mechanisms, SQL injection vulnerabilities, and wireless network security.

- **Network Intrusion Detection with Snort and Wireshark**  
  *Course Project - Intrusion Detection & Incident Response (Spring 2024)*  
  - Processed over 2,400 packets using Snort and Wireshark to detect anomalies such as bad checksum packets and unencrypted traffic.
  - Identified security vulnerabilities in SSLv2 and SSLv3 protocols, demonstrating the importance of encrypted communication for secure network operations.

---

### Networking and Database Projects
- **Network Configuration and Simulation with Cisco Packet Tracer**  
  *Course Project - Telecom and Networking (Fall 2022)*  
  - Configured and simulated a multi-device network environment using Cisco Packet Tracer, setting up static and dynamic IP addressing for various devices.
  - Troubleshot network issues, enhancing understanding of routing protocols, network management, and real-world network scenarios.

- **SQL Database Manipulation and Querying**  
  *Course Project - IS 4463 SQL Tactics (Spring 2024)*  
  - Designed and managed relational databases with tables such as `Birds` and `Books`, developing SQL queries to retrieve, update, and delete data.
  - Demonstrated proficiency in database management and SQL tactics by optimizing queries for better data handling.

---

### Personal Projects
- **Web Vulnerability Scanner**  
  *Personal Project (2023)*  
  - Developed a Python-based tool that scans websites for common vulnerabilities like XSS and SQL Injection, adhering to OWASP guidelines.
  - Automated the vulnerability detection process, providing reports on security risks to improve web application security.

- **DanOS Operating System Website**  
  *Personal Project (2023)*  
  - Built an interactive operating system simulation website using React and Next.js, showcasing coding skills and technical expertise in UI/UX design.
  - Designed the site as a platform for hosting portfolio projects with an intuitive and dynamic interface.

- **Dan3JS Interactive 3D Portfolio**  
  *Personal Project (2023)*  
  - Created a 3D portfolio using React and Three.js, featuring interactive animations and portfolio projects in a scene environment.
  - Emphasized visual engagement and interactivity, demonstrating advanced knowledge in web development and animation.

---

## Activities and Honors
- President's List Honoree – UTSA  
- Dean's List Honoree – UTSA  
- Member of National Society of Leadership and Success (June 2020)  
- Member of Golden Key International Honour Society (August 2022)  
- Felicity Karem Memorial Endowed Scholarship & Joint Admissions Scholarship  
- Cum Laude Graduate (2024)

---

## Volunteer Work
- **100 Club of San Antonio**  
  Assisted with community events and fundraising initiatives to support the families of first responders.
