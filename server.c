#include "appdynamics-cpp-sdk/include/appdynamics.h"
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#define MAX 800
#define PORT 8080
#define SA struct sockaddr

// Function designed for chat between client and server.
void func(int sockfd)
{
    char buff[MAX];
    int n;
    // infinite loop for chat
    for (;;) {
        
         bzero(buff, MAX);

        // read the message from client and copy it in buffer
        read(sockfd, buff, sizeof(buff));

        // print buffer which contains the client contents
        printf("\nFrom client: %s\t : ", buff);

// start the checkout transaction - be aware that buff contains the correlation header
appd_bt_handle btHandle = appd_bt_begin("Checkout",buff);
appd_bt_enable_snapshot(btHandle);

//        bzero(buff, MAX);
        n = 0;
        // copy server message in the buffer
//        while ((buff[n++] = getchar()) != '\n')
 //           ;
        char str[30];
//      strcpy(str, "response ");
        strcpy(str, buff);
        strcat(str, "\n");
        // and send that buffer to client
        write(sockfd, str, sizeof(str));

        // if msg contains "Exit" then server exit and chat ended.
        if (strncmp("exit", buff, 4) == 0) {
            printf("Server Exit...\n");
            break;
        }
// start the checkout transaction - be aware that buff contains the correlation header
//appd_bt_handle btHandle = appd_bt_begin("Checkout",buff);
//appd_bt_enable_snapshot(btHandle);
// declare a backend, only once for this SDK instance
const char backendOne[] = "liability check";
appd_backend_declare(APPD_BACKEND_HTTP,  backendOne);

appd_exitcall_handle inventory = appd_exitcall_begin(btHandle, backendOne);
const char* hdr = appd_exitcall_get_correlation_header(inventory);
appd_exitcall_set_details(inventory, "server backend call");
appd_exitcall_end(inventory);

// set the host property
int rc = appd_backend_set_identifying_property(backendOne, "HOST", "sqs-us-tdsklfjdkjfhsest-hostname");
//rc = appd_backend_set_identifying_property(backendOne, "PORT", "1010");
if (rc) {
   printf("Error: appd_backend_set_identifying_property: ");
}

// do not resolve the backend to the tier
rc = appd_backend_prevent_agent_resolution(backendOne);
if (rc) {
   printf("Error: appd_backend_prevent_agent_resolution");
}

// add the backend
rc = appd_backend_add(backendOne);
if (rc)
{
  printf("Error: appd_backend_add");
}

sleep(1);
// end the transaction
appd_bt_end(btHandle);

    }
}

// Driver function
int main()
{
const char APP_NAME[] = "HK-Server-Client";
const char TIER_NAME[] = "ServerTier";
const char NODE_NAME[] = "ServerNode1";
const char CONTROLLER_HOST[] = "channel.saas.appdynamics.com";
const int CONTROLLER_PORT = 443;
const char CONTROLLER_ACCOUNT[] = "channel";
const char CONTROLLER_ACCESS_KEY[] = "qrzwtryvbavv";
const int CONTROLLER_USE_SSL = 1;

struct appd_config* cfg2 = appd_config_init(); // appd_config_init() resets the configuration object and pass back an handle/pointer
appd_config_set_app_name(cfg2, APP_NAME);
appd_config_set_tier_name(cfg2, TIER_NAME);
appd_config_set_node_name(cfg2, NODE_NAME);
appd_config_set_controller_host(cfg2, CONTROLLER_HOST);
appd_config_set_controller_port(cfg2, CONTROLLER_PORT);
appd_config_set_controller_account(cfg2, CONTROLLER_ACCOUNT);
appd_config_set_controller_access_key(cfg2, CONTROLLER_ACCESS_KEY);
appd_config_set_controller_use_ssl(cfg2, CONTROLLER_USE_SSL);
int initRC = appd_sdk_init(cfg2);

if (initRC) {
      //std::cerr <<  "Error: sdk init: " << initRC << std::endl;
      printf("Error: sdk init: ");
        //printf(initRC);
 //     return -1;
}



    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully binded..\n");

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    }
    else
        printf("Server listening..\n");
    len = sizeof(cli);

    // Accept the data packet from client and verification
    connfd = accept(sockfd, (SA*)&cli, &len);
    if (connfd < 0) {
        printf("server accept failed...\n");
        exit(0);
    }
    else
        printf("server accept the client...\n");

    // Function for chatting between client and server
    func(connfd);

    // After chatting close the socket
    close(sockfd);
}
