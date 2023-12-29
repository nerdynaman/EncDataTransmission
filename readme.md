# Transmitting data over unsecured network using symmetric encryption and HMAC


## Overview

This program demonstrates a simple example of encrypted communication between a client and server using OpenSSL. The client sends encrypted data to the server using netcat, and the server decrypts and verifies the received data and further stores in a file "output.txt".


## Client Working
Client main process forks a new process so that in total we have two processes running. The parent process is responsible for generating encrypted data by reading from "input.txt" and the child process is responsible for sending the data to the server via sockets. Child recieves the data from parent through pipe.

### Encryption
The client uses AES-256-CBC encryption to encrypt data read from the "input.txt" file. An HMAC is calculated on the encrypted data.
Sending Data:
The client sends the HMAC, IV, ciphertext length, and encrypted data to the other process through pipe which further sends to the server via netcat command.

## Server Working
Server main process forks a new proces so that in total we have two processes running. The parent process is responsible for listening on port 9000 and the child process is responsible for reading the data from the pipe and decrypting it after verifying hmac.

### Decryption
The server uses AES-256-CBC decryption to decrypt the received data using a pre-shared key. 

`Saving to File:  The decrypted data is saved to the "output.txt" file.`

## Extras
PIPE:
while working with pipes we need to make sure that we close the unused ends of the pipe also with dup2 we need to make sure that stdout and stdin are properly replaced with ends of pipe.
If want to verify that hmac works properly, we can either use netcat to connect to server and modify some bytes of original payload and send it to server. Server will discard the data as hmac verification will fail. or while sending from client itself we can modify some bytes of original payload and send it to server.
max encryption size possible 1024 bytes.