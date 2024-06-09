#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define PORT 8080
#define MAX_KEYS 10
#define BUFFER_SIZE 1024

typedef struct {
    char key[BUFFER_SIZE];
    char value[BUFFER_SIZE];
} KeyValue;

KeyValue kv_store[MAX_KEYS];
int kv_count = 0;

int find_key(const char *key) {
    for (int i = 0; i < kv_count; i++) {
        if (strcmp(kv_store[i].key, key) == 0) {
            return i;
        }
    }
    return -1;
}

void trim_newline(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len-1] == '\n') {
        str[len-1] = '\0';
    }
}

void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);  // Free the allocated memory for the client socket descriptor
    char buffer[BUFFER_SIZE] = {0};
    int valread;

    while ((valread = read(client_socket, buffer, BUFFER_SIZE)) > 0) {
        buffer[valread] = '\0';
        printf("Received command: %s\n", buffer);  // Debugging line

        char *command = strtok(buffer, " ");
        char *key = strtok(NULL, " ");
        char *value = strtok(NULL, "\n");

        // Trim newline characters from key and value
        if (key != NULL) trim_newline(key);
        if (value != NULL) trim_newline(value);

        if (strcmp(command, "SET") == 0 && key && value) {
            printf("SET command with key: %s, value: %s\n", key, value);  // Debugging line
            int index = find_key(key);
            if (index == -1 && kv_count < MAX_KEYS) {
                strcpy(kv_store[kv_count].key, key);
                strcpy(kv_store[kv_count].value, value);
                kv_count++;
                send(client_socket, "+OK\n", strlen("+OK\n"), 0);
            } else if (index != -1) {
                strcpy(kv_store[index].value, value);
                send(client_socket, "+OK\n", strlen("+OK\n"), 0);
            } else {
                send(client_socket, "-ERR store full\n", strlen("-ERR store full\n"), 0);
            }
        } else if (strcmp(command, "GET") == 0 && key) {
            printf("GET command with key: %s\n", key);  // Debugging line
            int index = find_key(key);
            if (index != -1) {
                char response[BUFFER_SIZE];
                snprintf(response, sizeof(response), "$%ld\n%s\n", strlen(kv_store[index].value), kv_store[index].value);
                printf("Sending response: %s\n", response);  // Debugging line
                send(client_socket, response, strlen(response), 0);
            } else {
                send(client_socket, "$-1\n", strlen("$-1\n"), 0);
            }
        } else {
            send(client_socket, "-ERR unknown command\n", strlen("-ERR unknown command\n"), 0);
        }

        memset(buffer, 0, BUFFER_SIZE);
    }

    close(client_socket);
    return NULL;
}

int main(int argc, char *argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", port);

    while ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
        int *client_socket = malloc(sizeof(int));
        *client_socket = new_socket;

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, client_socket) != 0) {
            perror("pthread_create");
            free(client_socket);
        } else {
            pthread_detach(thread_id);
        }
    }

    if (new_socket < 0) {
        perror("accept");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    return 0;
}
