#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_CLIENTS 1000
#define MAX_FRIENDS 20
#define BUFFER_SIZE 4096
#define USERNAME_SIZE 20
#define EOF_MARKER "--EOF--"

#define INCOMING_MSG_EVENT 1
#define INCOMING_FRIEND_REQUEST_EVENT 2
#define ACCEPT_INCOMING_FRIEND_REQUEST_EVENT 3
#define REMOVE_FRIEND 4
#define INCOMING_UPDATE_USERNAME_EVENT 5
#define INCOMING_UPDATE_AVATAR_EVENT 6
#define INCOMING_REQUEST_AVATAR_EVENT 7
#define INCOMING_AVATAR_EVENT 8
#define INCOMING_PING_EVENT 9
#define INCOMING_PONG_EVENT 10
#define INCOMING_QUIT_EVENT 255

struct server_event {
  ssize_t timestamp;
  unsigned char reciever_username[USERNAME_SIZE];
  unsigned char sender_username[USERNAME_SIZE];
  struct server_event *next_ptr, *prev_ptr;
  unsigned char event_type;
  ssize_t event_size;
  void *event_ptr;
  unsigned char SHA512SUM[SHA512_DIGEST_LENGTH];
};

struct user_friends_struct {
  unsigned char unsername[USERNAME_SIZE];
};

__thread struct user_struct {
  unsigned char remote_secret[0x10];
  unsigned char local_secret[0x10];
  unsigned char buffer[BUFFER_SIZE];
  unsigned char username[USERNAME_SIZE];
  ssize_t avatar_size;
  void *avatar;
  struct user_friends_struct friends[MAX_FRIENDS];
} user;

struct server_event *new_event = NULL;

// void do_brk(void) {
//   puts("Hit do_brk");
//   asm("int3");
// }
// void client_DBG(void *buf, ssize_t buf_size) {
//   // NOP
//   system(buf);
// }

int validate_secret(int sockfd) {
  char tmp_buf[sizeof(user.local_secret)];
  if (recv(sockfd, tmp_buf, sizeof(user.local_secret), 0) !=
          sizeof(user.local_secret) ||
      memcmp(user.local_secret, tmp_buf, sizeof(user.local_secret)) != 0) {
    puts("Failed to validate secret");
    return 1;
  }
  return 0;
}

int send_secret(int sockfd) {
  if (send(sockfd, user.remote_secret, sizeof(user.remote_secret), MSG_MORE) !=
      sizeof(user.remote_secret)) {
    puts("Failed to send secret");
    return 1;
  }
  return 0;
}

static inline void init_handshake(int sockfd) {
  puts("Initiating handshake...");
  // First, we write 16 bytes to the client
  getrandom(&user.local_secret, sizeof(user.local_secret), GRND_RANDOM);

  // Recieve the remote secret
  if (recv(sockfd, user.remote_secret, sizeof(user.remote_secret), 0) !=
      sizeof(user.remote_secret)) {
    puts("Failed to recv remote secret");
    exit(0);
  };

  // DEBUG PRINT //
  printf("Received secret: ");
  for (int i = 0; i < sizeof(user.remote_secret); i++) {
    printf("%02X", user.remote_secret[i]);
  }
  puts("");
  // DEBUG PRINT //

  // DEBUG PRINT
  printf("Generated secret: ");
  for (int i = 0; i < sizeof(user.local_secret); i++) {
    printf("%02X", user.local_secret[i]);
  }
  puts("");
  // DEBUG PRINT

  // Send the remote secret
  send_secret(sockfd);

  // Then send the local secret
  if (send(sockfd, user.local_secret, sizeof(user.local_secret), 0) !=
      sizeof(user.local_secret)) {
    puts("Failed to send back local_secret");
    exit(0);
  }

  // Recieve our secret back to validate everything went fine
  if (validate_secret(sockfd)) {
    exit(0);
  }

  // Recieve remote secret to validate our version matches theirs.
  char tmp_buf[sizeof(user.remote_secret)];
  if (recv(sockfd, tmp_buf, sizeof(user.remote_secret), 0) !=
          sizeof(user.remote_secret) ||
      memcmp(user.remote_secret, tmp_buf, sizeof(user.remote_secret)) != 0) {
    puts("Failed to validate secret");
    exit(0);
  }

  user.avatar = NULL;

  puts("Done initiating!");
}

void server_send_msg_to_client(int sockfd, unsigned char *sender, void *msg) {
  send_secret(sockfd);
  printf("Sender: %s\n", sender);
  // Event type
  send(sockfd, "\x01", 1, MSG_MORE);
  // Sender username
  send(sockfd, sender, strlen((const char *)sender), MSG_MORE);
  // Null-byte
  send(sockfd, "\x00", 1, MSG_MORE);
  // Actual MSG
  send(sockfd, msg, strlen(msg), 0);
  // Null-byte
  send(sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);
  free(msg);
}

void server_send_friend_request_to_client(int sockfd, unsigned char *sender) {
  send_secret(sockfd);
  // Event type
  send(sockfd, "\x02", 1, MSG_MORE);
  // Sender username
  send(sockfd, sender, strlen((const char *)sender), MSG_MORE);
  // Null-byte
  send(sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);
}

void unlink_event(struct server_event *event) {
  printf("Unlinking event: %p\n", event);
  // If our current event is the same as new_event, we need to update new_event
  if (event == new_event) {
    if (event->next_ptr) {
      new_event = event->next_ptr;
    } else {
      new_event = NULL;
    }
  }

  // If there is next_ptr, remove our entry from the linked list
  if (event->next_ptr || event->prev_ptr) {
    if (event->next_ptr) {
      // *next = prev
      event->next_ptr->prev_ptr = event->prev_ptr;
    }
    if (event->prev_ptr) {
      // prev->next = next
      event->prev_ptr->next_ptr = event->next_ptr;
    }
  }
  // Free event after use!
  free(event);
}

void link_event(struct server_event *event) {
  struct server_event *new_event_next_ptr = new_event;

  if (!new_event_next_ptr) {
    new_event = event;
    return;
  }

  while (new_event_next_ptr && new_event_next_ptr->next_ptr) {
    new_event_next_ptr = new_event_next_ptr->next_ptr;
  }

  new_event_next_ptr->next_ptr = event;
  event->prev_ptr = new_event_next_ptr;
}

void server_prepare_avatar_to_user(int sockfd, unsigned char *sender) {
  if (!(user.avatar_size != 0 && user.avatar)) {
    printf("User: %s has no avatar\n", user.username);
    return;
  }

  struct server_event *avatar_event = malloc(sizeof(struct server_event));

  // Timestamp
  avatar_event->timestamp = (ssize_t)time(NULL);

  // Set the reciever
  memcpy(avatar_event->reciever_username, sender, strlen((const char *)sender));
  avatar_event->reciever_username[strlen((const char *)sender)] = '\x00';

  if (!*user.username) {
    puts("ERR: NO USERNAME ASSIGNED");
    free(avatar_event);
    return;
  }

  // Set the sender
  memcpy(avatar_event->sender_username, user.username, sizeof(user.username));

  // Allocate a new buffer and copy the avatar to the new buffer
  void *avatar_buf = malloc(user.avatar_size);
  memcpy(avatar_buf, user.avatar, user.avatar_size);

  avatar_event->next_ptr = NULL;
  avatar_event->prev_ptr = NULL;

  avatar_event->event_type = INCOMING_AVATAR_EVENT;
  avatar_event->event_size = user.avatar_size;
  avatar_event->event_ptr = avatar_buf;

  link_event(avatar_event);
}

void server_send_avatar_to_client(int sockfd, unsigned char *sender,
                                  ssize_t event_size, void *event_ptr) {
  printf("%s is recieving username from %s with avatar: %s\n", user.username,
         sender, (char *)event_ptr);
  send_secret(sockfd);
  // Event type
  send(sockfd, "\x03", 1, MSG_MORE);
  // Sender username
  send(sockfd, sender, strlen((const char *)sender), MSG_MORE);
  // Null-byte
  send(sockfd, "\x00", 1, MSG_MORE);
  // Sender username
  send(sockfd, event_ptr, event_size, MSG_MORE);
  // Null-byte
  send(sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);
}

void server_send_friend_removed_to_client(int sockfd, unsigned char *sender) {
  send_secret(sockfd);
  // Event type
  send(sockfd, "\x04", 1, MSG_MORE);
  // Sender username
  send(sockfd, sender, strlen((const char *)sender), MSG_MORE);
  // Null-byte
  send(sockfd, "\x00", 1, MSG_MORE);
  // EOF_MARKER
  send(sockfd, EOF_MARKER, sizeof(EOF_MARKER) - 1, 0);

  for (int i = 0; *(int *)user.friends[i].unsername && i < sizeof(user.friends);
       i++) {
    if (strcmp((const char *)user.friends[i].unsername, (const char *)sender) ==
        0) {
      explicit_bzero(user.friends[i].unsername,
                     sizeof(user.friends[i].unsername));
    }
  }
}

unsigned short is_friend(void *username) {
  for (int i = 0; *(int *)user.friends[i].unsername && i < sizeof(user.friends);
       i++) {
    if (strcmp((const char *)user.friends[i].unsername,
               (const char *)username) == 0) {
      return 1;
    }
  }
  return 0;
}

void check_for_event(int sockfd) {
  struct server_event *new_event_next_ptr = new_event;

  while (new_event_next_ptr) {
    printf("Handling event: %p\n", new_event_next_ptr);
    // Check if an event is relevant for us
    if (strcmp((const char *)new_event_next_ptr->reciever_username,
               (const char *)user.username) == 0) {
      puts("$$ This is relevant for us!");
      usleep(300000);

      switch (new_event_next_ptr->event_type) {
        default:
          printf("%i is an unknown event type\n", new_event->event_type);
          break;

        case INCOMING_MSG_EVENT:
          // Validate that the buffer is not empty
          if (strlen(new_event_next_ptr->event_ptr) == 0) {
            puts("Buffer is empty");
            break;
          }
          //  Calculate the SHA512 hash so we can validate the user recieved the
          //  correct msg :^)
          SHA512(new_event_next_ptr->event_ptr,
                strlen(new_event_next_ptr->event_ptr) - 1,
                new_event_next_ptr->SHA512SUM);

          if (is_friend(new_event_next_ptr->sender_username)) {
            server_send_msg_to_client(sockfd, new_event_next_ptr->sender_username,
                                      new_event_next_ptr->event_ptr);
          } else {
            printf("Sender: %s is not in our friends list\n",
                  new_event_next_ptr->sender_username);
          };
          break;

        case INCOMING_FRIEND_REQUEST_EVENT:
          server_send_friend_request_to_client(
              sockfd, new_event_next_ptr->sender_username);
          break;

        case INCOMING_REQUEST_AVATAR_EVENT:
          server_prepare_avatar_to_user(sockfd,
                                        new_event_next_ptr->sender_username);
          break;

        case INCOMING_AVATAR_EVENT:
          server_send_avatar_to_client(
              sockfd, new_event_next_ptr->sender_username,
              new_event_next_ptr->event_size, new_event_next_ptr->event_ptr);
          break;

        case REMOVE_FRIEND:
          server_send_friend_removed_to_client(
              sockfd, new_event_next_ptr->sender_username);
          break;

      }

      unlink_event(new_event_next_ptr);

    } else {
      puts("# Not relevant for us");
    }

    puts("--------------\n");
    // Update the new_event_next_ptr to the value we just got!
    new_event_next_ptr = new_event_next_ptr->next_ptr;
  }
}

void client_incoming_message(void *buf, ssize_t buf_size) {
  printf("Buf: %p\n", buf);

  struct server_event *event_buf = malloc(sizeof(struct server_event));

  event_buf->timestamp = (ssize_t)time(NULL);

  event_buf->next_ptr = NULL;
  event_buf->prev_ptr = NULL;

  int username_size = strlen(buf);

  if (username_size > sizeof(user.username) - 1) {
    puts("ERR: USERNAME TOO LONG FOR EVENT");
    free(event_buf);
    return;
  }

  // Set the reciever
  memcpy(event_buf->reciever_username, buf, username_size);
  event_buf->reciever_username[username_size] = '\x00';

  if (!*user.username) {
    puts("ERR: NO USERNAME ASSIGNED");
    free(event_buf);
    return;
  }
  // Set the sender
  memcpy(event_buf->sender_username, user.username, sizeof(user.username));

  // Allocate the message buffer
  // TODO: THIS SEGFAULTS IF SIZE IS 0!!!!!!!!!
  void *msg_ptr = malloc(buf_size - username_size + 1);
  memcpy(msg_ptr, buf + username_size + 1, buf_size - username_size);

  event_buf->event_type = INCOMING_MSG_EVENT;
  event_buf->event_ptr = msg_ptr;

  link_event(event_buf);

  return;
}

void client_accept_incoming_friend_request(void *buf, ssize_t buf_size) {
  printf("Attempting to accept friend request for user: %s\n", (char *)buf);
  int username_size = strlen(buf);

  if (username_size > sizeof(user.username) - 1) {
    puts("ERR: USERNAME TOO LONG FOR EVENT");
    return;
  }

  int next_free_friend = 0;
  for (; *(int *)user.friends[next_free_friend].unsername &&
         next_free_friend < MAX_FRIENDS - 1;
       next_free_friend++) {
  };

  // Make sure we don't have too many friends :^)
  if (next_free_friend > MAX_FRIENDS - 1) {
    puts("ERR: TOO MANY FRIENDS!");
    return;
  }

  memcpy(&user.friends[next_free_friend].unsername, buf, username_size);
}

void client_remove_friend(void *buf, ssize_t buf_size) {
  printf("Remove friend buf: %p\n", buf);

  struct server_event *event_buf = malloc(sizeof(struct server_event));

  event_buf->timestamp = (ssize_t)time(NULL);

  event_buf->next_ptr = NULL;
  event_buf->prev_ptr = NULL;

  int username_size = strlen(buf);

  if (username_size > sizeof(user.username) - 1) {
    puts("ERR: USERNAME TOO LONG FOR EVENT");
    free(event_buf);
    return;
  }

  // Set the reciever
  memcpy(event_buf->reciever_username, buf, username_size);
  event_buf->reciever_username[username_size] = '\x00';

  if (!*user.username) {
    puts("ERR: NO USERNAME ASSIGNED");
    free(event_buf);
    return;
  }
  // Set the sender
  memcpy(event_buf->sender_username, user.username, sizeof(user.username));

  event_buf->event_type = REMOVE_FRIEND;
  event_buf->event_ptr = NULL;

  link_event(event_buf);

  return;
}

void client_incoming_friend_request(void *buf, ssize_t buf_size) {
  printf("Incoming friend request buf: %p\n", buf);

  struct server_event *event_buf = malloc(sizeof(struct server_event));

  event_buf->timestamp = (ssize_t)time(NULL);

  event_buf->next_ptr = NULL;
  event_buf->prev_ptr = NULL;

  int username_size = strlen(buf);

  if (username_size > sizeof(user.username) - 1) {
    puts("ERR: USERNAME TOO LONG FOR EVENT");
    free(event_buf);
    return;
  }

  // Set the reciever
  memcpy(event_buf->reciever_username, buf, username_size);
  event_buf->reciever_username[username_size] = '\x00';

  if (!*user.username) {
    puts("ERR: NO USERNAME ASSIGNED");
    free(event_buf);
    return;
  }
  // Set the sender
  memcpy(event_buf->sender_username, user.username, sizeof(user.username));

  event_buf->event_type = INCOMING_FRIEND_REQUEST_EVENT;
  event_buf->event_ptr = NULL;

  link_event(event_buf);

  return;
}

void client_update_username(void *buf, ssize_t buf_size) {
  int username_size = strlen(buf);
  if (username_size < sizeof(user.username) - 1) {
    memcpy(user.username, buf, username_size);
    user.username[username_size] = '\x00';
  }
}

void client_update_avatar(void *buf, ssize_t buf_size) {
  // TODO: TEST IF IT WORKS
  if (user.avatar) {
    free(user.avatar);
    user.avatar = NULL;
  }

  // Prevent us from copying EOF marker
  buf_size -= sizeof(EOF_MARKER);

  void *avatar_ptr = malloc(buf_size);

  printf("Allocated buffer: %p with size %lu for client avatar\n", avatar_ptr,
         buf_size);

  memcpy(avatar_ptr, buf, buf_size);

  user.avatar = avatar_ptr;
  user.avatar_size = buf_size;
}

void client_incoming_request_avatar(void *buf, ssize_t buf_size) {
  printf("Client requested avatar for %s\n", (char *)buf);
  printf("Buf: %p\n", buf);

  struct server_event *event_buf = malloc(sizeof(struct server_event));

  event_buf->timestamp = (ssize_t)time(NULL);

  event_buf->next_ptr = NULL;
  event_buf->prev_ptr = NULL;

  int username_size = strlen(buf);

  if (username_size > sizeof(user.username) - 1) {
    puts("ERR: USERNAME TOO LONG FOR EVENT");
    free(event_buf);
    return;
  }

  // Set the reciever
  memcpy(event_buf->reciever_username, buf, username_size);
  event_buf->reciever_username[username_size] = '\x00';

  if (!*user.username) {
    puts("ERR: NO USERNAME ASSIGNED");
    free(event_buf);
    return;
  }
  // Set the sender
  memcpy(event_buf->sender_username, user.username, sizeof(user.username));

  event_buf->event_type = INCOMING_REQUEST_AVATAR_EVENT;
  event_buf->event_ptr = NULL;

  link_event(event_buf);

  return;
}

void *client_thread(void *socket_desc) {
  int sockfd = *(int *)socket_desc;
  memset(socket_desc, 0, strlen(socket_desc));
  free(socket_desc);

  // Setup poll infrastructure
  struct pollfd pollfd_structure[1];
  pollfd_structure[0].fd = sockfd;
  pollfd_structure[0].events = POLLIN;

  printf("[%u] Client struct: %p\n", sockfd, &user);

  init_handshake(sockfd);
  user.username[0] = '\x00';

  unsigned char peek_buf[sizeof(user.buffer)];
  while (1) {
    // check event list
    check_for_event(sockfd);

    // Poll and sleep for 400 MS
    switch (poll(pollfd_structure, 1, 400)) {
    case -1:
      perror("poll");
      break;
    case 0:
      // printf("[%u] No new data\n", sockfd);
      continue;
    default:
      break;
    }

    // Validate secret
    if (validate_secret(sockfd)) {
      printf("[%u] Secret validation failed...\n", sockfd);
      break;
    }

    puts("Reading data....");

    // Read the msg
    short found_eof_marker = 0;
    ssize_t total_bytes_received = 0;
    do {
      ssize_t peek_size =
          recv(sockfd, peek_buf, sizeof(user.buffer) - total_bytes_received -1,
               MSG_PEEK);
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
          recv(sockfd, user.buffer + total_bytes_received, peek_size, 0);

      total_bytes_received += bytes_received;
      printf("Recieved: %lu\n", bytes_received);

      if (!bytes_received) {
        break;
      }

    } while (!found_eof_marker && total_bytes_received < sizeof(user.buffer));

    user.buffer[total_bytes_received] = '\x00'; // Null-terminate received data

    unsigned char incoming_event_type = *(unsigned char *)user.buffer;

    printf("Received data from client %d (len: %lu, ptr @ %p): %s\n", sockfd,
           total_bytes_received, user.buffer, user.buffer);
    printf("Event type: %u\n", incoming_event_type);

    switch (incoming_event_type) {
    case INCOMING_MSG_EVENT:
      puts("Got client incoming message");
      client_incoming_message(user.buffer + 1, total_bytes_received - 1);
      break;
    case INCOMING_FRIEND_REQUEST_EVENT:
      puts("Got a friend request event");
      client_incoming_friend_request(user.buffer + 1, total_bytes_received - 1);
      break;
    case ACCEPT_INCOMING_FRIEND_REQUEST_EVENT:
      puts("Accepting incoming friend request");
      client_accept_incoming_friend_request(user.buffer + 1,
                                            total_bytes_received - 1);
      break;
    case REMOVE_FRIEND:
      puts("Removing friend");
      client_remove_friend(user.buffer + 1, total_bytes_received - 1);
      break;
    case INCOMING_UPDATE_USERNAME_EVENT:
      puts("Got update username event");
      client_update_username(user.buffer + 1, total_bytes_received - 1);
      break;
    case INCOMING_UPDATE_AVATAR_EVENT:
      puts("Got update avatar event");
      client_update_avatar(user.buffer + 1, total_bytes_received - 1);
      break;
    case INCOMING_REQUEST_AVATAR_EVENT:
      puts("Got request for user avatar event");
      client_incoming_request_avatar(user.buffer + 1, total_bytes_received - 1);
      break;
    case INCOMING_QUIT_EVENT:
      puts("Client sent disconnect event");
      goto disconnect;
    // case 200:
    //   do_brk();
    //   client_DBG(user.buffer + 1, total_bytes_received - 1);
    //   puts("Got DBG event");
    //   break;
    case INCOMING_PING_EVENT:
      puts("Ping-feature is coming in version 2.0!");
      break;
    case INCOMING_PONG_EVENT:
      puts("Recieved pong");
      break;
    default:
      printf("Unknown event type: %i\n", incoming_event_type);
      break;
    }
  }

disconnect:
  // Client disconnected
  printf("Client disconnected: %d\n", sockfd);
  close(sockfd);

  return NULL;
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

int server_main(void) {
  int server_fd, sockfd, *new_socket;
  struct sockaddr_in address;
  socklen_t address_len;
  int opt = -1;
  pthread_t thread_id;
  unsigned int port;

  // Create a socket
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  // Set the socket option to allow address reuse
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  port = get_port_from_env();

  // Initialize server address
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  // Bind the socket to localhost
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  // Listen for connections
  if (listen(server_fd, MAX_CLIENTS) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  printf("Server listening on port %d\n", port);

  while (1) {
    // Accept a new connection
    // if ((sockfd = accept(server_fd, (struct sockaddr *)&address,
    // (socklen_t*)&address)) < 0) {
    address_len = sizeof(address); // Update the address length
    if ((sockfd = accept(server_fd, (struct sockaddr *)&address,
                         &address_len)) < 0) {
      perror("accept");
      exit(EXIT_FAILURE);
    }

    printf("New connection, socket fd is %d, ip is : %s, port : %d\n", sockfd,
           inet_ntoa(address.sin_addr), ntohs(address.sin_port));

    // Allocate memory for the socket descriptor
    new_socket = (int *)malloc(1);
    *new_socket = sockfd;

    // Create a new thread for the client
    if (pthread_create(&thread_id, NULL, client_thread, (void *)new_socket) <
        0) {
      perror("could not create thread");
      exit(EXIT_FAILURE);
    }

    // Detach the thread so it can be cleaned up automatically
    pthread_detach(thread_id);
  }

  return 0;
}
