#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>

#define BUFFERLENGTH 256

typedef struct Query {
    unsigned int ip;
    unsigned int port;
    struct Query* next;
} Query;

typedef struct Rule {
    unsigned int start_ip;
    unsigned int end_ip;
    unsigned int start_port;
    unsigned int end_port;
    struct Query* queries;
    struct Rule* next;
} Rule;

typedef struct Request {
    char* request;
    struct Request* next;
} Request;

// Global list head for rules
Rule* rules_head = NULL;

// Global mutex for rules list
pthread_mutex_t rules_mutex = PTHREAD_MUTEX_INITIALIZER;
// Global mutex for stored
pthread_mutex_t stored_mutex = PTHREAD_MUTEX_INITIALIZER;
// List to store requests for 'R' command
Request* request_head = NULL;

bool is_running = true;

void ctrl_c_handler(int signum) {
    is_running = false;
}


void error(const char *msg) {
    perror(msg);
    exit(1);
}

uint32_t ip_to_int(const char *ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    return ntohl(addr.s_addr);
}

char* int_to_ip(const unsigned int ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char* address = (char*)malloc(16);
    inet_ntop(AF_INET, &(addr), address, 16);
    return address;
}


bool validate_single_ip(const char *ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

bool validate_single_port(int port) {
    return port >= 0 && port <= 65535;
}


void store_request(const char *request) {
    if (request == NULL || strlen(request) == 0) return;  // Ignore empty requests

    Request* new_request = (Request*)malloc(sizeof (Request));
    new_request->request = (char*)malloc(strlen(request) + 1);
    strncpy(new_request->request, request, strlen(request));
    new_request->request[strlen(request)] = '\0';
    new_request->next = NULL;

    pthread_mutex_lock(&stored_mutex);
    if (request_head == NULL)
        request_head = new_request;
    else {
        Request* current = request_head;
        while(current->next != NULL)
            current = current->next;
        current->next = new_request;
    }
    pthread_mutex_unlock(&stored_mutex);
}

void clear_request() {
    if (request_head == NULL)
        return;

    Request* current = request_head;
    while (current != NULL) {
        Request* temp = current;
        current = current->next;
        free(temp->request);
        free(temp);
        request_head = current;
    }
}

bool equal_rules(const Rule left, const Rule right) {
    return left.start_ip == right.start_ip && left.end_ip == right.end_ip &&
            left.start_port == right.start_port && left.end_port == right.end_port;
}

Rule* create_rule(const char* s_rule) {
    Rule* rule = (Rule*)malloc(sizeof (Rule));
    if (rule == NULL)
        return NULL;
    char ip_part[32], port_part[32];
    if (sscanf(s_rule, "%31s %31s", ip_part, port_part) != 2) {
        free(rule);
        return NULL;
    }

    char ip_start[16], ip_end[16];
    int count_parts = sscanf(ip_part, "%15[^-]-%15s", ip_start, ip_end);
    if (count_parts == 1) {
        if (!validate_single_ip(ip_start)) {
            free(rule);
            return NULL;
        }
        rule->start_ip = ip_to_int(ip_start);
        rule->end_ip = rule->start_ip;
    }
    else if (count_parts == 2) {
        if (!validate_single_ip(ip_start) || !validate_single_ip(ip_end)) {
            free(rule);
            return NULL;
        }
        rule->start_ip = ip_to_int(ip_start);
        rule->end_ip = ip_to_int(ip_end);
        if (rule->start_ip > rule->end_ip) {
            free(rule);
            return NULL;
        }
    }
    else {
        free(rule);
        return NULL;
    }

    unsigned int port_start, port_end;
    count_parts = sscanf(port_part, "%d-%d", &port_start, &port_end);
    if (count_parts == 1) {
        if (!validate_single_port(port_start)) {
            free(rule);
            return NULL;
        }
        rule->start_port = port_start;
        rule->end_port = rule->start_port;
    }
    else if (count_parts == 2) {
        if (!validate_single_port(port_start) || !validate_single_port(port_end) || (port_start > port_end)) {
            free(rule);
            return NULL;
        }
        rule->start_port = port_start;
        rule->end_port = port_end;
    }
    else {
        free(rule);
        return NULL;
    }

    rule->queries = NULL;
    rule->next = NULL;

    return rule;
}

bool add_rule(const char* s_rule) {

    Rule* new_rule = create_rule(s_rule);
    if (new_rule == NULL)
        return false;

    pthread_mutex_lock(&rules_mutex);
    if (rules_head == NULL)
        rules_head = new_rule;
    else {
        Rule* current_rule = rules_head;
        while (current_rule->next != NULL)
            current_rule = current_rule->next;
        current_rule->next = new_rule;
    }
    pthread_mutex_unlock(&rules_mutex);

    return true;
}

void free_rule(Rule* rule) {
    Query* query = rule->queries;
    while (query != NULL) {
        Query* temp = query;
        query = query->next;
        free(temp);
    }
    rule->queries = NULL;
    free(rule);
}

int delete_rule(const char* rule_to_delete) {
    if (rules_head == NULL)
        return 1; // Invalid Rule

    Rule* rule = create_rule(rule_to_delete);
    if (rule == NULL)
        return -1;

    pthread_mutex_lock(&rules_mutex);
    Rule *prev = NULL, *current = rules_head;

    if (equal_rules(*rule, *rules_head)) {
        rules_head = current->next;
        free_rule(current);
        free_rule(rule);
        pthread_mutex_unlock(&rules_mutex);
        return 0; // Rule Delete
    }

    current = rules_head->next;
    prev = rules_head;
    // Search for the rule
    while (current != NULL) {
        if (equal_rules(*rule, *current)) {
            prev->next = current->next;
            free_rule(current);
            free_rule(rule);
            pthread_mutex_unlock(&rules_mutex);
            return 0; // Rule Deleted
        }
        prev = prev->next;
        current = current->next;
    }
    free_rule(rule);
    pthread_mutex_unlock(&rules_mutex);
    return 1; // Rule not found
}

void clear_rules() {
    if (rules_head == NULL)
        return;

    Rule* current = rules_head;
    while (current != NULL) {
        Rule* temp = current;
        current = current->next;
        rules_head = current;
        free_rule(temp);
    }

}

void add_query_to_rule(Rule *rule, const unsigned ip, int port) {
    Query* new_query = malloc(sizeof(Query));
    if (!new_query) return;

    new_query->ip = ip;
    new_query->port = port;
    new_query->next = NULL;

    if (rule->queries == NULL) {
        rule->queries = new_query;
        return;
    }

    Query* query = rule->queries;
    while (query->next != NULL) {
        query = query->next;
    }
    query->next = new_query;
}

char* print_rule(Rule rule) {
    char* rule_msg = (char*)malloc(BUFFERLENGTH);
    char ip_parts[33];
    if (rule.start_ip == rule.end_ip) {
        char* start_ip = int_to_ip(rule.start_ip);
        snprintf(ip_parts, sizeof (ip_parts), "%s", start_ip);
        free(start_ip);
    }
    else {
        char* start_ip = int_to_ip(rule.start_ip);
        char* end_ip = int_to_ip(rule.end_ip);
        snprintf(ip_parts, sizeof (ip_parts), "%s-%s", start_ip, end_ip);
        free(start_ip);
        free(end_ip);
    }
    char port_parts[11];
    if (rule.start_port == rule.end_port)
        snprintf(port_parts, sizeof (port_parts), "%d", rule.start_port);
    else
        snprintf(port_parts, sizeof (port_parts), "%d-%d", rule.start_port, rule.end_port);
    snprintf(rule_msg, BUFFERLENGTH, "Rule: %s %s\n", ip_parts, port_parts);

    Query *query = rule.queries;
    while (query != NULL) {
        char query_info[BUFFERLENGTH];
        char* ip = int_to_ip(query->ip);
        snprintf(query_info, sizeof(query_info), "\tQuery: %s %d\n", ip, query->port);
        strcat(rule_msg, query_info);
        free(ip);
        query = query->next;
    }

    return rule_msg;
}

void list_rules(int newsockfd) {
    if (rules_head == NULL) {
        write(newsockfd, "No rules available", 18);
        return;
    }

    char list_rules[BUFFERLENGTH * 10] = "";

    pthread_mutex_lock(&rules_mutex);
    Rule* temp = rules_head;

    while (temp != NULL) {
        char* rule_msg = print_rule(*temp);
        strcat(list_rules, rule_msg);
        free(rule_msg);
        temp = temp->next;
    }
    pthread_mutex_unlock(&rules_mutex);
    write(newsockfd, list_rules, strlen(list_rules));
}

void list_requests(int newsockfd) {
    if (request_head == NULL) {
        write(newsockfd, "No commands available", 21);
        return;
    }
    char list_commands[BUFFERLENGTH * 10] = "";

    pthread_mutex_lock(&stored_mutex);
    Request* request = request_head;
    while (request != NULL) {
        strcat(list_commands, request->request);
        strcat(list_commands, "\n");
        request = request->next;
    }
    pthread_mutex_unlock(&stored_mutex);
    write(newsockfd, list_commands, strlen(list_commands));
}

bool check_ip_port_against_rule(const Rule rule, const unsigned int ip, const unsigned int port) {
    return (rule.start_ip <= ip) && (rule.end_ip >= ip) && (rule.start_port <= port) && (rule.end_port >= port);
}

void handle_check_ip_port(int newsockfd, const unsigned int ip, const unsigned int port) {
    if (rules_head == NULL)
        return;
    pthread_mutex_lock(&rules_mutex);
    Rule* rule = rules_head;
    bool accepted = false;

    while (rule != NULL) {
        if (check_ip_port_against_rule(*rule, ip, port)) {
            add_query_to_rule(rule, ip, port);
            accepted = true;
            break;
        }
        rule = rule->next;
    }
    pthread_mutex_unlock(&rules_mutex);
    write(newsockfd, accepted ? "Connection accepted" : "Connection rejected", strlen(accepted ? "Connection accepted" : "Connection rejected"));

}

char *trim_whitespace(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return str;
}

// Function to handle and process commands
void handle_command(const char *command, int fd) {
    switch (command[0]) {
        case 'A':
            if (strlen(command) > 2 && command[1] == ' ') {
                if (add_rule(command + 2)) {
                    dprintf(fd, "Rule added");
                } else {
                    dprintf(fd, "Invalid rule");
                }
            } else {
                dprintf(fd, "Invalid format for A command");
            }
            break;

        case 'D':
            if (strlen(command) > 2 && command[1] == ' ') {
                int code = delete_rule(command + 2);
                if (code == 0) {
                    dprintf(fd, "Rule deleted");
                } else if (code == -1) {
                    dprintf(fd, "Rule invalid");
                } else if (code == 1) {
                    dprintf(fd, "Rule not found");
                }
            } else {
                dprintf(fd, "Invalid format for D command");
            }
            break;

        case 'C':
            if (strlen(command) > 2 && command[1] == ' ') {
                char ip[16];
                int port;
                if (sscanf(command + 2, "%15s %d", ip, &port) == 2 && validate_single_ip(ip) && validate_single_port(port)) {
                    handle_check_ip_port(fd, ip_to_int(ip), port);  // Use provided fd (either socket or stdout)
                } else {
                    dprintf(fd, "Illegal IP address or port specified");
                }
            } else {
                dprintf(fd, "Invalid format for C command");
            }
            break;

        case 'L':
            if (strlen(command) == 1) {
                list_rules(fd);  // Use provided fd (either socket or stdout)
            } else {
                dprintf(fd, "Invalid format for L command");
            }
            break;

        case 'R':
            if (strlen(command) == 1) {
                list_requests(fd);  // Use provided fd (either socket or stdout)
            } else {
                dprintf(fd, "Invalid format for R command");
            }
            break;

        default:
            dprintf(fd, "Illegal request");
            break;
    }
}

// processRequest function for server mode
void *processRequest(void *args) {
    int* newsockfd = (int *)args;
    char buffer[BUFFERLENGTH];

    bzero(buffer, BUFFERLENGTH);
    int n = read(*newsockfd, buffer, BUFFERLENGTH - 1);
    if (n < 0) {
        error("ERROR reading from socket");
    }

    char *command = trim_whitespace(buffer);
    store_request(command);

    // Use handle_command for processing
    handle_command(command, *newsockfd);

    close(*newsockfd);
    pthread_exit(NULL);
    free(newsockfd);
    free(command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "ERROR, no port provided\n");
        exit(1);
    }

//    if ( signal(SIGINT, ctrl_c_handler) == SIG_ERR )
//        exit(1);

    if (strcmp(argv[1], "-i") == 0) {
        // Interactive mode
        char buffer[BUFFERLENGTH];

        while (is_running) {
            if (fgets(buffer, BUFFERLENGTH, stdin) == NULL) {
                break;
            }
            buffer[strcspn(buffer, "\n")] = 0;  // Remove trailing newline

            if (strlen(buffer) == 0) {
                continue;  // Ignore empty lines
            }

            char *command = trim_whitespace(buffer);

            // Add a condition to allow quitting interactive mode (e.g., by typing "quit")
            if (strcmp(command, "quit") == 0) {
                printf("Exiting interactive mode\n");
                break;
            }

            store_request(command);
            // Process command in interactive mode
            handle_command(command, STDOUT_FILENO);
            //free(command);
            dprintf(STDOUT_FILENO, "\n");
        }

        clear_request();
        clear_rules();
        return 0;
    }

    // Server mode
    int portno = atoi(argv[1]);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error("ERROR opening socket");

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) error("ERROR on binding");

    listen(sockfd, 5);

    while (is_running) {
        struct sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);
        int *newsockfd = malloc(sizeof(int));

        *newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (*newsockfd < 0) {
            free(newsockfd);
            error("ERROR on accept");
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, processRequest, newsockfd) != 0) {
            free(newsockfd);
            error("ERROR creating thread");
        }
        pthread_detach(thread);
    }

    clear_request();
    clear_rules();
    close(sockfd);
    return 0;
}
