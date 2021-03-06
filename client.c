#include "appdynamics-cpp-sdk/include/appdynamics.h"
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#define MAX 80
#define PORT 8080
#define SA struct sockaddr
void func(int sockfd, int limit)
{
    char buff[MAX];
    int n;
    for (int i = 0; i != limit; i++) {

       // start the "Checkout" transaction
       appd_bt_handle btHandle = appd_bt_begin("Checkout", NULL);
       appd_bt_enable_snapshot(btHandle);

       //const char* APPD_CORRELATION_HEADER_NAME = "singularityheader";

       // declare a backend, only once for this SDK instance
       const char backendOne[] = "inventory";
       appd_backend_declare(APPD_BACKEND_WEBSPHEREMQ,  backendOne);

       //Start an exit call to backendOne
       appd_exitcall_handle inventory = appd_exitcall_begin(btHandle, backendOne);
       const char* hdr = appd_exitcall_get_correlation_header(inventory);
       appd_exitcall_set_details(inventory, "client backend call");

       //bzero(buff, sizeof(buff));
       //strcpy(buff, "hi");
       if(i== limit)  strcpy(buff, "exit");
       printf("to Server : %s\n", hdr);

       //Send correlation header (hdr) to the server
       write(sockfd, hdr, strlen(hdr));

       
       bzero(buff, sizeof(buff));
       read(sockfd, buff, sizeof(hdr));
       if ((strncmp(buff, "exit", 4)) == 0) {
           printf("Client Exit...\n");
           break;
       }
       //Lets add a delay (>= 1ms)so we see some time reflected in AppD controller for the exit call
       usleep(1000);
       appd_exitcall_end(inventory);

       // set the host property for backendOne backend
       int rc = appd_backend_set_identifying_property(backendOne, "HOST", "127.0.0.1");
       //rc = appd_backend_set_identifying_property(backendOne, "PORT", "1010");
       if (rc) {
          printf("Error: appd_backend_set_identifying_property: ");
       }
 
       // do not resolve the backend to the tier - ClientTier talks directly to ServerTier in the flow map
       // Uncomment this if you want to see a gray cloud icon representing the backend in AppD's flow map
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

int main(int argc, char *argv[])
{

const char APP_NAME[] = "HK-Server-Client";
const char TIER_NAME[] = "ClientTier";
const char NODE_NAME[] = "ClientNode1";
const char CONTROLLER_HOST[] = "channel.saas.appdynamics.com";
const int CONTROLLER_PORT = 443;
const char CONTROLLER_ACCOUNT[] = "channel";
const char CONTROLLER_ACCESS_KEY[] = "qrzwtryvbavv";
const int CONTROLLER_USE_SSL = 1;

struct appd_config* cfg = appd_config_init(); // appd_config_init() resets the configuration object and pass back an handle/pointer
appd_config_set_app_name(cfg, APP_NAME);
appd_config_set_tier_name(cfg, TIER_NAME);
appd_config_set_node_name(cfg, NODE_NAME);
appd_config_set_controller_host(cfg, CONTROLLER_HOST);
appd_config_set_controller_port(cfg, CONTROLLER_PORT);
appd_config_set_controller_account(cfg, CONTROLLER_ACCOUNT);
appd_config_set_controller_access_key(cfg, CONTROLLER_ACCESS_KEY);
appd_config_set_controller_use_ssl(cfg, CONTROLLER_USE_SSL);
int initRC = appd_sdk_init(cfg);

int limit = atoi(argv[1]); //limit = -1 => infinite loop

if (initRC) {
      //std::cerr <<  "Error: sdk init: " << initRC << std::endl;
      printf("Error: sdk init: ");
        //printf(initRC);
      return -1;
}

        int sockfd, connfd;
        struct sockaddr_in servaddr, cli;

        // socket create and varification
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
        servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        servaddr.sin_port = htons(PORT);

        // connect the client socket to server socket
        if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
                printf("connection with the server failed...\n");
                exit(0);
        }
        else
                printf("connected to the server..\n");
// function for chat
        func(sockfd,limit);

        // close the socket
        close(sockfd);
}


