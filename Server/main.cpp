#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>//windows sockets function
#include <windows.h>
#include <time.h>
#include <math.h>

#pragma comment(lib, "ws2_32.lib")//wink winsock library

#define PORT 8080//server port
#define MAX_CLIENTS 10//max clients that can be connected
#define BUFFER_SIZE 1024//max size of msg
#define NAME_LEN 50//max name length

typedef struct{
    struct sockaddr_in addr;//client ip and port
    char name[NAME_LEN];//client username
    int active;//to indiacate active clients
    time_t last_activity; //time of last msg
}Client;

typedef struct{
    long long modulus;
    long long exponent;
}RSA_Key;

//rsa keys for the server
RSA_Key server_public_key;
RSA_Key server_private_key;

//generating rsa keys
void generate_rsa_keys(){
    long long p=61;//using fixed primes, in real use, generate random primes
    long long q=53;
    long long n=p*q;
    long long phi=(p-1)*(q-1);
    long long e=17;//public exponent coprime with phi
    long long d=2753;//private exponent

    server_public_key.modulus = n;
    server_public_key.exponent = e;
    server_private_key.modulus = n;
    server_private_key.exponent = d;

    printf("Generated RSA keys:\n");
    printf("Public: (n=%lld, e=%lld)\n", n, e);
    printf("Private: (n=%lld, d=%lld)\n", n, d);
}
//modular exponentiation function
long long mod_exp(long long a, long long b, long long m) {
    long long result = 1;
    a = a % m;
    while (b > 0) {
        if (b % 2 == 1) {
            result = (result * a) % m;
        }
        a = (a * a) % m;
        b = b / 2;
    }
    return result;
}

long long rsa_crypt(long long msg, RSA_Key key) {
    return mod_exp(msg, key.exponent, key.modulus);
}

Client clients[MAX_CLIENTS];//array to store clients
int client_count=0;

int is_same_client(struct sockaddr_in *a, struct sockaddr_in *b){//to check if two clients are same
    return(a->sin_addr.s_addr==b->sin_addr.s_addr&&a->sin_port==b->sin_port);

}

void add_client(SOCKET sock, struct sockaddr_in *addr, char *name){
    for(int i=0;i<client_count;i++){
        if(is_same_client(&clients[i].addr,addr)){//to check if the client exists
            clients[i].last_activity=time(NULL);
            return;
        }
    }

    if(client_count<MAX_CLIENTS){
        clients[client_count].addr=*addr;
        strncpy(clients[client_count].name,name,NAME_LEN-1);
        clients[client_count].active=1;
        clients[client_count].last_activity=time(NULL);
        printf("%s joined the chat\n",name);
        client_count++;
    }else{
        printf("Max clients reached. %s cannot join\n",name);
    }

    char join_msg[BUFFER_SIZE];
    snprintf(join_msg, BUFFER_SIZE, "%s has joined the chat.", name);
    for(int i = 0; i < client_count - 1; i++) {
        if(clients[i].active) {
            sendto(sock, join_msg, strlen(join_msg), 0, (struct sockaddr*)&clients[i].addr, sizeof(clients[i].addr));
        }
    }
}

void remove_inactive_clients(SOCKET sock) {
    time_t now = time(NULL);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].active && (now - clients[i].last_activity) > 60) {
            printf("%s timed out\n", clients[i].name);
            char timeout_msg[BUFFER_SIZE];
            snprintf(timeout_msg, BUFFER_SIZE, "%s has been disconnected due to inactivity.", clients[i].name);
            for (int j = 0; j < client_count; j++) {
                if (clients[j].active && j != i) {
                    sendto(sock, timeout_msg, strlen(timeout_msg), 0, (struct sockaddr*)&clients[j].addr, sizeof(clients[j].addr));
                }
            }
            clients[i].active = 0;
        }
    }
}

void broadcast(SOCKET sock, char *msg, struct sockaddr_in *sender_addr) {
    char formatted_msg[BUFFER_SIZE];
    char sender_name[NAME_LEN] = "Unknown";
    for (int i = 0; i < client_count; i++) {
        if (is_same_client(&clients[i].addr, sender_addr)) {
            strcpy(sender_name, clients[i].name);
            break;
        }
    }

    // Display message on server
    printf("%s: %s\n", sender_name, msg);

    snprintf(formatted_msg, BUFFER_SIZE, "%s: %s", sender_name, msg);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].active && !is_same_client(&clients[i].addr, sender_addr)) {
            sendto(sock, formatted_msg, strlen(formatted_msg), 0, (struct sockaddr*)&clients[i].addr, sizeof(clients[i].addr));
        }
    }
}

void send_private(SOCKET sock, int recipient_id, char *msg, struct sockaddr_in *sender_addr) {
    if (recipient_id < 0 || recipient_id >= client_count || !clients[recipient_id].active) {
        printf("Invalid client id\n");
        return;
    }
    char sender_name[NAME_LEN] = "Unknown";
    for (int i = 0; i < client_count; i++) {
        if (is_same_client(&clients[i].addr, sender_addr)) {
            strcpy(sender_name, clients[i].name);
            break;
        }
    }

    //check if msg id encrypted
    if(strncmp(msg, "enc:",4)==0){
        char *encrypted_msg=msg+4;
        long long numeric_msg=atoll(encrypted_msg);
        //decrypt msg with server's private key
    long long decrypted_num=rsa_crypt(numeric_msg,server_private_key);
    //convert back to string
    char decrypted_msg[BUFFER_SIZE];
    sprintf(decrypted_msg,"%lld",decrypted_num);

    // Display private message on server
    printf("Private message from %s to %s: %s\n", sender_name, clients[recipient_id].name, msg);

    char private_msg[BUFFER_SIZE];
    snprintf(private_msg, BUFFER_SIZE, "Private message from %s: %s", sender_name, msg);
    sendto(sock, private_msg, strlen(private_msg), 0, (struct sockaddr*)&clients[recipient_id].addr, sizeof(clients[recipient_id].addr));


    }else{
        printf("Private message from %s to %s: %s\n", sender_name, clients[recipient_id].name, msg);

    char private_msg[BUFFER_SIZE];
    snprintf(private_msg, BUFFER_SIZE, "Private message from %s: %s", sender_name, msg);
    sendto(sock, private_msg, strlen(private_msg), 0, (struct sockaddr*)&clients[recipient_id].addr, sizeof(clients[recipient_id].addr));


    }
    char confirmation[BUFFER_SIZE];
    snprintf(confirmation, BUFFER_SIZE, "Sent to %s", clients[recipient_id].name);
    sendto(sock, confirmation, strlen(confirmation), 0, (struct sockaddr*)sender_addr, sizeof(*sender_addr));

}

int main(){
    generate_rsa_keys();
    WSADATA wsa;// receives details about windows sockets implementation
    SOCKET server_socket;//creating udp socket
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len=sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    //initializing winsock
    if(WSAStartup(MAKEWORD(2,2),&wsa)!=0){
        printf("Winsock init failed\n");
        return 1;
    }
    //udp socket creation
    server_socket=socket(AF_INET, SOCK_DGRAM, 0);//ipv4, udp
    if(server_socket==INVALID_SOCKET){
        printf("Socket creation failed\n");
        return 1;
    }
    //configure server
    server_addr.sin_family=AF_INET;
    server_addr.sin_addr.s_addr=INADDR_ANY;//accept any ip
    server_addr.sin_port=htons(PORT);//convert to byte
    //bind the socket
    if(bind(server_socket,(struct sockaddr*)&server_addr, sizeof(server_addr))==SOCKET_ERROR){
        printf("Bind failed\n");
        closesocket(server_socket);
        return 1;
    }
    printf("Server running on port %d\n",PORT);
    while(1){
        memset(buffer,0,BUFFER_SIZE);
        int recv_len=recvfrom(server_socket,buffer,BUFFER_SIZE,0,(struct sockaddr*)&client_addr,&client_addr_len);
        if(recv_len==SOCKET_ERROR){
            printf("Receive error\n");
            continue;
        }
        buffer[recv_len]='\0';
        //handling users
        if(strncmp(buffer,"Register: ",9)==0){
            char *name=buffer+9;
            add_client(server_socket, &client_addr, name);
        }
        //handling private messages
        else if(strcmp(buffer, "/list") == 0) {
            char list_msg[BUFFER_SIZE] = "Online users:\n";
            for(int i = 0; i < client_count; i++) {
                if(clients[i].active) {
                    char entry[100];
                    snprintf(entry, sizeof(entry), "[%d] %s\n", i, clients[i].name);
                    strncat(list_msg, entry, BUFFER_SIZE - strlen(list_msg) - 1);
                }
            }
            sendto(server_socket, list_msg, strlen(list_msg), 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
        }
            else if(strncmp(buffer, "/private ", 9) == 0) {
                char *args = buffer + 9;
                char *id_str = strtok(args, " ");
                char *msg = strtok(NULL, "");

                if(id_str && msg) {
                    int recipient_id = atoi(id_str);
                    send_private(server_socket, recipient_id, msg, &client_addr);
                } else {
                    char *error = "Invalid private message format. Use: /private <id> <message>";
                    sendto(server_socket, error, strlen(error), 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
                }
            }
        else{
            broadcast(server_socket, buffer, &client_addr);
        }
        remove_inactive_clients(server_socket);
    }
    closesocket(server_socket);
    WSACleanup();
    return 0;
}
