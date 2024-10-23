#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <netdb.h>

#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 4096
#define USERNAME_SIZE 20
#define MAX_FRIENDS 20
#define EOF_MARKER "--EOF--"

#define INCOMING_MSG_EVENT 1
#define INCOMING_FRIEND_REQUEST_EVENT 2
#define INCOMING_AVATAR_FOR_USER_EVENT 3
#define INCOMING_FRIEND_REMOVED_EVENT 4
#define INCOMING_PING_EVENT 5


#define FRIEND_FRIEND 0
#define FRIEND_PENDING 1

struct user_session {
  unsigned char remote_secret[0x10];
  unsigned char local_secret[0x10];
  unsigned char username[USERNAME_SIZE];
  int sockfd;
};

struct message_event {
  unsigned char reciever_username[USERNAME_SIZE];
  short unsigned msg_len;
  void *msg;
};

struct user {
  unsigned char username[USERNAME_SIZE];
  unsigned short friend_status;
  ssize_t avatar_size;
  void *avatar;
};

struct user_session *session;
struct user *friends[MAX_FRIENDS];

void menu_prompt(void) { puts("Press ^C to access the menu!"); }

void do_brk(void) {
  puts("Hit do_brk");
  asm("brk 0");
}

void validate_secret(void) {
  char tmp_buf[sizeof(session->local_secret)];
  if (recv(session->sockfd, tmp_buf, sizeof(session->local_secret), 0) !=
          sizeof(session->local_secret) ||
      memcmp(session->local_secret, tmp_buf, sizeof(session->local_secret)) !=
          0) {
    puts("Failed to validate secret");
    exit(0);
  }
}

void send_secret(void) {
  if (send(session->sockfd, session->remote_secret, sizeof(session->remote_secret),
           MSG_MORE) != sizeof(session->remote_secret)) {
    puts("Failed to send secret");
    exit(0);
  }
}


void set_username(void *username) {
  send_secret();
  // Event type
  send(session->sockfd, "\x05", 1, MSG_MORE);
  // Sender username
  send(session->sockfd, username, strlen((const char *)username), MSG_MORE);
  // Null-byte
  send(session->sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(session->sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);
}

void set_avatar(void *avatar, ssize_t size) {
  send_secret();
  // Event type
  send(session->sockfd, "\x06", 1, MSG_MORE);
  // Send the avatar
  send(session->sockfd, avatar, size, MSG_MORE);
  // Null-byte
  send(session->sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(session->sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);
}

void send_message(struct message_event *msg) {
  send_secret();
  // Event type
  send(session->sockfd, "\x01", 1, MSG_MORE);
  // Sender username
  send(session->sockfd, msg->reciever_username,
       strlen((const char *)msg->reciever_username), MSG_MORE);
  // Null-byte
  send(session->sockfd, "\x00", 1, MSG_MORE);
  // Message
  send(session->sockfd, msg->msg, msg->msg_len, MSG_MORE);
  // Null-byte
  send(session->sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(session->sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);

  free(msg->msg);
  free(msg);
}

void read_and_set_username(void) {
  printf("Username > ");
  scanf("%19s", session->username);
  session->username[sizeof(session->username) - 1] = '\x00';
  set_username(session->username);
}

void read_and_set_avatar(void) {
  unsigned int size = 0;
  printf("Avatar size > ");
  scanf("%u", &size);
  // Take BUFFER_SIZE minus 2 (the event number and ending null-byte) and
  // sizeof(EOF_MARKER)
  if (size >= BUFFER_SIZE - 2 - sizeof(EOF_MARKER)) {
    puts("Avatar too large for buffer");
    return;
  }

  void *avatar_buf = malloc(size);

  printf("Avatar > ");
  read(STDIN_FILENO, avatar_buf, size);

  set_avatar(avatar_buf, size);

  free(avatar_buf);
}

void accept_friend_request(unsigned char *username) {
  // Send secret
  send_secret();
  // Event type
  send(session->sockfd, "\x03", 1, MSG_MORE);
  // Sender username
  send(session->sockfd, username, strlen((const char *)username), MSG_MORE);
  // Null-byte
  send(session->sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(session->sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);
}

void read_and_send_friend_request(void) {
  struct message_event *msg = malloc(sizeof(struct message_event));

  printf("Reciever username > ");
  scanf("%19s", msg->reciever_username);
  msg->reciever_username[sizeof(msg->reciever_username) - 1] = '\x00';

  send_secret();
  // Event type
  send(session->sockfd, "\x02", 1, MSG_MORE);
  // Sender username
  send(session->sockfd, msg->reciever_username,
       strlen((const char *)msg->reciever_username), MSG_MORE);
  // Null-byte
  send(session->sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(session->sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);

  // Accept it on our behalf such that we can recieve incoming from user
  accept_friend_request(msg->reciever_username);

  free(msg);
}

void read_and_remove_friend(void) {
  struct message_event *msg = malloc(sizeof(struct message_event));

  printf("Username to remove> ");
  scanf("%19s", msg->reciever_username);
  msg->reciever_username[sizeof(msg->reciever_username) - 1] = '\x00';

  send_secret();
  // Event type
  send(session->sockfd, "\x04", 1, MSG_MORE);
  // Send username
  send(session->sockfd, msg->reciever_username,
       strlen((const char *)msg->reciever_username), MSG_MORE);
  // Null-byte
  send(session->sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(session->sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);
}

void request_avatar(unsigned char *username) {
  printf("Requesting avatar for %s...\n", username);
  // Secret
  send_secret();
  // Event type
  send(session->sockfd, "\x07", 1, MSG_MORE);
  // Request the avatar for username
  send(session->sockfd, username, strlen((const char *)username), MSG_MORE);
  // Null-byte
  send(session->sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(session->sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);
}

void read_and_accept_friend_request(void) {
  struct message_event *msg = malloc(sizeof(struct message_event));

  printf("Username to accept > ");
  scanf("%19s", msg->reciever_username);
  msg->reciever_username[sizeof(msg->reciever_username) - 1] = '\x00';

  for (int i = 0; i < MAX_FRIENDS; i++) {
    if (friends[i] && friends[i]->friend_status == FRIEND_PENDING &&
        strcmp((char *)friends[i]->username, (char *)msg->reciever_username) ==
            0) {
      puts("Found friend in pending.. Adding!");
      accept_friend_request(msg->reciever_username);

      // Set friend status to friend
      friends[i]->friend_status = FRIEND_FRIEND;

      request_avatar(friends[i]->username);
      goto free;
    }
  }
  printf("User: %s is not a pending friend\n", msg->reciever_username);

free:
  free(msg);
}

void read_and_send_message(void) {
  struct message_event *msg = malloc(sizeof(struct message_event));

  printf("Reciever username > ");
  scanf("%19s", msg->reciever_username);
  msg->reciever_username[sizeof(msg->reciever_username) - 1] = '\x00';

  printf("Message len > ");
  scanf("%hu", &msg->msg_len);

  msg->msg = malloc(msg->msg_len);

  printf("Message > ");

  read(STDIN_FILENO, msg->msg, msg->msg_len);

  send_message(msg);
}

void do_quit(void) {
  send_secret();
  // Send exit code
  send(session->sockfd, "\xff", 1, MSG_MORE);
  // EOF_MARKER
  send(session->sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);
}

void handle_friend_request(char *buffer) {
  for (int i = 0; i < MAX_FRIENDS - 1; i++) {
    if (!friends[i]) {
      printf("Handling friend: %i - username: %s\n", i, buffer);

      // Allocate user buffer
      friends[i] = malloc(sizeof(struct user));
      explicit_bzero(friends[i], sizeof(struct user));

      // Copy the buffer to the newly allocated username buffer
      memcpy(friends[i]->username, buffer, sizeof(friends[i]->username));

      // Set avatar to 0 in size to indicate no avatar
      friends[i]->avatar_size = 0;

      // Set status to pending
      friends[i]->friend_status = FRIEND_PENDING;

      return;
    }
  }
  puts("No space left in friends list... Being popular has its downsides");
}

void send_pong(void) {
  puts("Sending pong");
  // Secret
  send_secret();
  // Event type
  send(session->sockfd, "\x09", 1, MSG_MORE);
  // EOF_MARKER
  send(session->sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);
}

void print_incoming_msg(void *buffer, ssize_t size) {
  char *sender = buffer;
  char *msg = buffer + strlen(sender) + 1;
  ssize_t msg_len = size - strlen(sender) - sizeof(EOF_MARKER) - 1;
  puts("|===============================|");
  printf("| NEW MESSAGE FROM: %s\t|\n", sender);
  puts("|===============================|");
  printf("> ");
  write(STDOUT_FILENO, msg, msg_len);
}

void handle_friend_remove(char *buffer) {
  for (int i = 0; i < MAX_FRIENDS - 1; i++) {
    if (friends[i] && strcmp((char *)friends[i]->username, buffer) == 0) {
      // Free user avatar :^)
      free(friends[i]->avatar);
      friends[i]->friend_status = FRIEND_PENDING;
      return;
    }
  }
  puts("Friend not in friends list");
}

void handle_avatar_for_user(void *buffer, ssize_t size) {
  printf("Handling incoming avatar for %s\n", (char *)buffer);
  ssize_t avatar_size = size - strlen(buffer) - sizeof(EOF_MARKER) - 1;
  void *avatar_buf = buffer + strlen(buffer) + 1;

  for (int i = 0; i < MAX_FRIENDS; i++) {
    // BUG HERE! WE DO NOT CHECK FOR PENDING WHICH IS A UAF!!!
    if (friends[i] && strcmp((char *)friends[i]->username, buffer) == 0) {
      puts("Found friend in friends list");
      if (!friends[i]->avatar) {
        puts("User did not have avatar. Allocating new buffer");
        friends[i]->avatar = malloc(avatar_size);
        printf("%p with size: %lu\n", friends[i]->avatar, avatar_size);
      }
      // The obvious OOB write is bait to make people run in to MTE
      friends[i]->avatar_size = avatar_size;
      memcpy(friends[i]->avatar, avatar_buf, avatar_size);
    }
  }
}

void action_menu(int sig) {
  unsigned short choice;
  if (sig != 2) {
    exit(1);
  }

  printf("\e[1;1H\e[2J");
  puts(""); // Because ^c looks ugly
  puts("Choose option!");
  puts("\t0 - Continue");
  puts("\t1 - Set username");
  puts("\t2 - Send message to user");
  puts("\t3 - Send friend request");
  puts("\t4 - Accept friend request");
  puts("\t5 - Remove friend");
  puts("\t6 - Update user avatar");
  puts("\t9 - quit");

  printf("\n> ");
  scanf("%hu", &choice);

  switch (choice) {
  case 0:
    break;
  case 1:
    read_and_set_username();
    break;
  case 2:
    read_and_send_message();
    break;
  case 3:
    read_and_send_friend_request();
    break;
  case 4:
    read_and_accept_friend_request();
    break;
  case 5:
    read_and_remove_friend();
    break;
  case 6:
    read_and_set_avatar();
    break;

  case 9:
  default:
    puts("Bye bye!");
    do_quit();
    exit(0);
    break;
  }

  printf("\e[1;1H\e[2J\nContinuing...\n");
  menu_prompt();
  return;
}

static inline void set_random_username(void) {
  // Generate and set a random username
  getrandom(&session->username, sizeof(session->username)-1, GRND_RANDOM);
  session->username[sizeof(session->username) - 1] = '\x00';

  set_username(session->username);
}

static inline void init_handshake(void) {
  puts("Initiating handshake...");

  // First, we write 16 bytes to the client
  getrandom(&session->local_secret, sizeof(session->local_secret), GRND_RANDOM);

  // DEBUG PRINT
  printf("Generated secret: ");
  for (int i = 0; i < sizeof(session->local_secret); i++) {
    printf("%02X", session->local_secret[i]);
  }
  puts("");
  // DEBUG PRINT

  // Send the client secret to server
  if (send(session->sockfd, session->local_secret, sizeof(session->local_secret),
           0) != sizeof(session->local_secret)) {
    puts("Failed to write secret to client");
    exit(0);
  }

  // Recieve our secret back to validate everything went fine
  validate_secret();

  // Recieve the remote secret
  if (recv(session->sockfd, session->remote_secret, sizeof(session->remote_secret),
           0) != sizeof(session->remote_secret)) {
    puts("Failed to recv remote secret");
    exit(0);
  };

  // DEBUG PRINT //
  printf("Received secret: ");
  for (int i = 0; i < sizeof(session->remote_secret); i++) {
    printf("%02X", session->remote_secret[i]);
  }
  puts("");
  // DEBUG PRINT //

  // Send the remote secret
  send_secret();

  // Then send the local secret
  if (send(session->sockfd, session->local_secret, sizeof(session->local_secret),
           0) != sizeof(session->local_secret)) {
    puts("Failed to send back session->local_secret");
    exit(0);
  }

  // Set a random username
  set_random_username();

  puts("Done initiating!");
}

void main_logic(void) {
  char buffer[BUFFER_SIZE];

  init_handshake();
  menu_prompt();

  // Setup poll infrastructure
  struct pollfd pollfd_structure[1];
  pollfd_structure[0].fd = session->sockfd;
  pollfd_structure[0].events = POLLIN;

  unsigned char peek_buf[BUFFER_SIZE];
  while (1) {
    // Poll and sleep for 400 MS
    switch (poll(pollfd_structure, 1, 400)) {
    case -1:
      // perror("poll");
      break;
    case 0:
      // printf("[%u] No new data\n", session->sockfd);
      continue;
    default:
      break;
    }

    // Validate secret
    validate_secret();

    puts("Reading data....");

    // Read the msg
    short found_eof_marker = 0;
    ssize_t total_bytes_received = 0;
    do {
      ssize_t peek_size = recv(session->sockfd, peek_buf,
                               sizeof(buffer) - total_bytes_received, MSG_PEEK);
      if (peek_size > sizeof(EOF_MARKER) - 1) {
        for (int i = 0; i < peek_size - sizeof(EOF_MARKER) + 2; ++i) {
          if (!memcmp(EOF_MARKER, peek_buf + i, sizeof(EOF_MARKER) - 1)) {
            printf("Found EOF marker @ %i\n", i);
            peek_size = i + sizeof(EOF_MARKER) - 1;
            found_eof_marker = 1;
            break;
          }
        }
      }

      ssize_t bytes_received =
          recv(session->sockfd, buffer + total_bytes_received, peek_size, 0);

      total_bytes_received += bytes_received;
      printf("Recieved: %lu\n", bytes_received);

      if (!bytes_received) {
        break;
      }

    } while (!found_eof_marker && total_bytes_received < sizeof(buffer));

    // OUTSIDE OF THE RECIEVE LOOP!!!

    buffer[total_bytes_received] = '\x00'; // Null-terminate received data

    unsigned char incoming_event_type = *(unsigned char *)buffer;

    printf("Received data from client %d (len: %lu, ptr @ %p): %s\n",
           session->sockfd, total_bytes_received, buffer, buffer);
    printf("Event type: %u\n", incoming_event_type);

    switch (incoming_event_type) {
    case INCOMING_MSG_EVENT:
      puts("Got client incoming message");
      print_incoming_msg((void *)&buffer + 1, total_bytes_received - 1);
      break;
    case INCOMING_FRIEND_REQUEST_EVENT:
      puts("Got a friend request event");
      handle_friend_request((char *)&buffer + 1);
      break;
    case INCOMING_AVATAR_FOR_USER_EVENT:
      puts("Got incoming avatar update for user");
      handle_avatar_for_user((void *)&buffer + 1, total_bytes_received - 1);
      break;
    case INCOMING_FRIEND_REMOVED_EVENT:
      puts("Got friend remove event for user");
      handle_friend_remove((void *)&buffer + 1);
      break;
    case INCOMING_PING_EVENT:
      puts("Got ping");
      send_pong();
      break;
    default:
      printf("Unknown event type: %i\n", incoming_event_type);
      break;
    }
  }
}

unsigned int get_port_from_env(void) {
    char *port_str = getenv("PORT");

    if (port_str != NULL) {
        // Convert the environment variable to an unsigned int
        char *endptr;
        unsigned int port = strtoul(port_str, &endptr, 10);

        // Check for conversion errors
        if (*endptr != '\0') {
            printf("Conversion error: '%s' is not a valid unsigned int\n", port_str);
            exit(0);
        }

        return port;
    } else {
        puts("No port specified via PORT env, using 1337");
        return 1337;
    }
}

int connect_server(void) {
  struct sockaddr_in server_addr;
  unsigned int port;
  // Create socket
  if ((session->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Socket creation error");
    exit(EXIT_FAILURE);
  }

  port = get_port_from_env();
  // Initialize server address struct
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);

  // Resolve server hostname
  struct hostent *server_hostname = gethostbyname("server");
  if (server_hostname == NULL) {
    fprintf(stderr, "Server hostname not found, assuming 127.0.0.1 \n");
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    //exit(EXIT_FAILURE);
  } else {
    memcpy(&server_addr.sin_addr.s_addr, server_hostname->h_addr, server_hostname->h_length);
  }


  // Connect to server
  if (connect(session->sockfd, (struct sockaddr *)&server_addr,
              sizeof(server_addr)) < 0) {
    perror("Connection failed");
    exit(EXIT_FAILURE);
  }

  printf("Connected to server\n");

  return session->sockfd;
}

void init(void) {
  // Turn off buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  setbuf(stdin, NULL);

  session = (struct user_session*)malloc(sizeof(struct user_session));

  explicit_bzero(friends, sizeof(friends));
  explicit_bzero(session, sizeof(struct user_session));
}

int main(void) {
  init();

  session->sockfd = connect_server();
  // At this point, we have initialized
  signal(SIGINT, action_menu);
  main_logic();
  close(session->sockfd);
}
