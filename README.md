# rsa-private-chat

Compiling the Server:
1. Open command prompt
2. Navigate to  server folder
3. Compile using gcc: 
gcc server.c -o server.exe -lws2_32

Compliling the client:
1. Open new command prompt window
2. Navigate to client folder
3. Compile using gcc: 
gcc client.c -o client.exe -lws2_32

Running the chat application:
1. start the server: 
server.exe

2. Start clients, can start multiple clients on different terminals,
and run: 
client.exe
Enter name and the chat begins.

To exit or shutdown server:
press ctrl+c
