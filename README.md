Art3misRAT

Art3misRAT is a Remote Access Trojan (RAT) designed for Windows environments and written in Rust.
Features:
    PowerShell Execution: Executes PowerShell commands with the ability to return the output to the server.
    Persistence Mechanism: Ensures the RAT starts with Windows by adding a registry key.
    AES-256 Encryption: Encrypts all communications between the RAT and the command-and-control (C2) server using AES-256 encryption.
    Environment Awareness: Detects if running in a virtualized environment and exits if so, to prevent analysis.

Design

Art3misRAT consists of two main components:

    Art3misRAT (Client): The malware that runs on the infected machine, establishes a connection to the C2 server, and awaits commands.
    Art3misServer (Server): The C2 server that listens for incoming connections from infected machines and sends commands to them.

Art3misRAT (Client)

    Establishes a connection to the C2 server.
    Sets up persistence by adding a registry key.
    Listens for incoming commands, decrypts them, and executes them.
    Returns the output of the commands to the C2 server.

Art3misServer (Server)

    Listens on a specified port for incoming connections.
    Sends encrypted commands to the connected clients.
    Receives and decrypts the responses from the clients.
    
Commands

    !!kill: Terminates the RAT process.
    !!powershell or !!ps: Executes a PowerShell command.
        Example: !!powershell Get-Process
        Example: !!ps Get-Process
