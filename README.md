# Art3misRAT

Art3misRAT is a Remote Access Trojan (RAT) designed for Windows environments and written in Rust.

## Features:

PowerShell Execution: Executes PowerShell commands with the ability to return the output to the server.

Persistence Mechanism: Ensures the RAT starts with Windows by adding a registry key.

AES-256 Encryption: Encrypts all communications between the RAT and the command-and-control (C2) server using AES-256 encryption.

Environment Awareness: Detects if running in a virtualized environment and exits if so, to prevent analysis.

## v1.1.0 Update: Encrypted Delivery via Loader for Dynamic Code at Runtime

Dynamic Code Loading: The RAT payload is stored in encrypted form and only decrypted at runtime, preventing static analysis and signature-based detection.

## Design

Art3misRAT consists of two main components:


Art3misRAT (Client)

The malware that runs on the infected machine.
Establishes a connection to the C2 server.
Sets up persistence by adding a registry key.
Listens for incoming commands, decrypts them, and executes them.
Returns the output of the commands to the C2 server.

Art3misServer (Server)

Listens on a specified port for incoming connections.
Sends encrypted commands to the connected clients.
Receives and decrypts the responses from the clients.
    
## Commands

!!kill: Terminates the RAT process.

Example:

    !!kill
    
!!powershell or !!ps: Executes a PowerShell command.

Example: 

    !!powershell Get-Process

    !!ps Get-Process

## Building for the first time

Fist off, youll need Rust if you dont have it already. You can download it here (https://www.rust-lang.org/tools/install)

For the sake of this explanation, I will assume you exctract the Art3mis folder directly to C:\

Once that is complete, open a new terminal and follow along

### Building the Server

Build the Server:

    cd C:\Art3mis\Art3misServer\target

    cargo build --release

You can run the server by going to C:\Art3mis\Art3misServer\target\release and running Art3misServer.exe

    cd C:\Art3mis\Art3misServer\target\release
    
    ./Art3misServer

### Building the RAT

Note: by default the ip for the remote host ((where the RAT will connect back to)) is set to 127.0.0.1 aka local host
This will work great for testing it on your local machine, however if you want to deploy the RAT to a different system 
than where the server is running, you will need to go into the art3mis_rat.rs file and change the ip to the public facing
ip of the server before building.

Build the RAT:

    cd C:\Art3mis\Art3misRAT

    cargo build --release

At this point the Art3misRAT.exe can be found in C:\Art3mis\Art3misRAT\target\release, and can be used as is, however there are
additional steps if you want to use the Encrypted Loader Feature as well.

You can run the rat as is without the loader by going to C:\Art3mis\Art3misRAT\target\release and running Art3misRAT.exe.
If you want to use the loader, or embed the payload in a delivery mechanism, you can skip this step.

Running Art3misRAT

    cd C:\Art3mis\Art3misRAT\target\release
    
    ./Art3misRAT

### Building the Loader

The loader is depandant on the file art3mis_chunks.rs which contains the encrypted and chucked binary of Art3misRAT.exe. art3mis_chunks.rs is produced by RAT_Encryptor.py.

Building art3mis_chunks.rs

    cd C:\Art3mis

    //check if python is installed, if not install it
    python

    //install the cryptography module if you haven't done so already
    pip install cryptography

    //run the encryptor
    python RAT_Encryptor.py

When the script is complete, art3mis_chunks.rs will be saved to to the correct location and you can continue to build the loader.

Build the Loader

    cd C:\Art3mis\Art3misLoader

    cargo build --release

At this point the art3misloader can be found in C:\Art3mis\Art3misLoader\target\release, and can be used as is, however there are
additional steps if you want to use the embed the payload in a delivery mechanism. If you want to embed the payload in a delivery mechanism, you can skip this step and continue to delivery.

Running the Loader

    cd C:\Art3mis\Art3misLoader\target\release

    ./art3misloader


## Delivery

The Art3misRAT executable was embedded into the Art3misRATDeliveryDemo.docm document using the RATEncoder script to demonstrate potential delivery methods.
Check out my other repo RATEncoder to get the RATEncoder to reliably embed Art3misRAT and other executable payloads into Microsoft Word Documents.

RATEncoder (https://github.com/gsoukupuiw/RAT_Encoder)

### Embedding Art3misRAT in a word document

First, youll need the RATEncoder script. For the sake of this tutorial, I will assume you downloaded it to C:\Art3mis.

You'll need to open the file with the text editor of your choice and modify the following lines

    exe_path = r"C:\Users\path_to_file.exe"
    
    output_path = r"C:\Users\path_to_file.txt"

Assuming you want to encode the Art3misRAT build WITHOUT the Encrypted Loader feature, use the following

    exe_path = r"C:\Art3mis\Art3misRAT\target\release\Art3misRAT.exe"
    
    output_path = r"C:\Art3mis\Art3misEncoded.txt"

OR if you want to encode the Art3misRAT build WITH the Encrypted Loader feature, use the following

    exe_path = r"C:\Art3mis\Art3misLoader\target\release\art3misloader.exe"
    
    output_path = r"C:\Art3mis\Art3misEncoded.txt"

Once you have done this, create a new Word Document, and save it as a .docm with macros enabled file. Then use alt F11 to open the macro editor, go to insert, new module, and copy and paste the entire contents of Art3misEncoded.txt into the module. 
Note: you will need to remove the fist "base64String =" from the file as it will cause a compile error with VBA. You can then save the macro and resave the file and Art3misRAT will then execute the next time the file is opened.
    

## Discalimer

This software is provided for educational and research purposes only. The developers are not responsible for any misuse or damage caused by this software. Use it responsibly and legally.
