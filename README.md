# Secure Instant Messaging Application

### Requirements

 * Python 3.10+
 * [Google Protocol Buffers v3](https://developers.google.com/protocol-buffers/docs/tutorials)

### Project Set Up

 * Install `Protocol Buffers` v3.0
    ```
     sudo apt-get update && sudo apt-get install protobuf-compiler
    ```
   
 * Compile the _.proto_ file
    ```
     protoc --python_out=. pb-team11.proto
    ```

 * Provide `Execute` option to the files
   ```
      chmod 764 chat_server.py
   ```
   ```
      chmod 764 chat_client.py
   ```

 * In one terminal window run:
    ```
     ./chat_server.py -sp <SERVER_PORT>
    ```

 * In another window run:
    ```
     ./chat_client.py -sip <SERVER_IP> -sp <SERVER_PORT> -u <CLLIENT_USERNAME>
    ```
### User Sign Up

 * Generate `SRP salt` and `SRP verification key`s for a user using the below command

   ```
      ./srp_credentials_creator.py -u <username> -p <password>
   ```
   
 * Once the above program runs successfully, copy the generated credentials into `config/config.py` **entirely**

   ````
      secure_storage = {
         'username' : (SRP_salt, SRP_vkey)
      }
   ````
   * **Example:**

     ![Adding User Credentials](Docs/configuration.png)

 * `Restart` the server and clients

### Commands available for the client

 * `SIGNIN -` To authenticate to the server
 * `LIST -` To list all the available (or online) users (or clients)
 * `SEND <username> <message> -` To send a message to the user represented by the `username`
 * `BYE -` To exit the chat room

### Contributors

  * [Abhiram Sarja](https://www.linkedin.com/in/asarja/) | sarja.a@northeastern.edu
  * [Simran Sohal](sohal.s@northeastern.edu) | sohal.s@northeastern.edu
