# Project Idea

- **Project title:** Automated Digital Evidence Collection System for DFIR/CA
- **Scope:** Collect evidence from both Windows and Linux systems.
- **Functionality:** Collect digital artifacts relevant to investigations in specific scenarios, such as web shells, process injection, and malicious services.
- **System architecture:**
  - A central server coordinates artifact collection across the monitored hosts.
  - Each monitored host runs a service/daemon that listens for instructions from the central server. The daemon identifies the host's role (e.g., file server, web server, or client) and uses that role, together with the investigation objective, to decide whether to collect artifacts and where to collect them. For example, when investigating whether an attacker has created a web shell, a daemon on a web server collects suspicious files from the web server's upload directories, such as unexpected `.aspx` or `.php` files.
- **Technology:** The final version should use high-performance technologies such as Rust or Go; prototypes may use simpler technologies.
- **Implementation order:** Design and implement the Linux system first, then extend it to Windows.
