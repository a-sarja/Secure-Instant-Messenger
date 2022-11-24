# Secure Instant Messaging Application

### Requirements

 * Python 3.10+
 * [Google Protocol Buffers](https://developers.google.com/protocol-buffers/docs/tutorials) v3

### Project Set Up

 * Install Protocol Buffers v3.0
    ```
     $ sudo apt-get update && sudo apt-get install protobuf-compiler
    ```
   
 * Compile the _.proto_ file
    ```
     $ protoc --python_out=. pb-team11.proto
    ```

 * In one terminal window run:
    ```
     $ ./chat_server.py -sp <SERVER_PORT>
    ```
 * In another window run:
    ```
     $ ./chat_client.py -sip <SERVER_IP> -sp <SERVER_PORT> -u <CLLIENT_USERNAME>
    ```

### Commands available for the client

 * `SIGNIN -` To log-in to the server
 * `LIST -` To list all the available (or online) users (or clients)
 * `BYE -` To exit the chat room

### Contributors
  * [Abhiram Sarja](https://www.linkedin.com/in/asarja/) | sarja.a@northeastern.edu
  * [Simran Sohal](sohal.s@northeastern.edu) | sohal.s@northeastern.edu
