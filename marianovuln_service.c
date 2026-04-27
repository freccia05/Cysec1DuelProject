/*
 * vuln_service.c — Intentionally vulnerable network service
 * FOR EDUCATIONAL USE ONLY — Cybersecurity lab environment
 *
 * Vulnerability: stack-based buffer overflow in handle_client()
 * The fixed-size buffer 'buf[64]' is filled via recv() with no length check.
 *
 * Compile (with protections disabled for lab realism):
 *   gcc -o vuln_service vuln_service.c \
 *       -fno-stack-protector \
 *       -z execstack \
 *       -no-pie \
 *       -m32
 *
 * Then run: ./vuln_service
 * Listens on TCP port 9999
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 9999
#define BACKLOG 1

/* ------------------------------------------------------------------ */
/* The vulnerable function                                              */
/* A fixed 64-byte buffer is populated from raw network input with no  */
/* length validation — classic stack smash target.                      */
/* ------------------------------------------------------------------ */
void handle_client(int client_fd) {
    char buf[256];         /* <-- increased buffer size to prevent overflow */
    char response[128];

    /* Send banner */
    const char *banner = "KEEPALIVE service ready. Send your heartbeat:\n";
    send(client_fd, banner, strlen(banner), 0);

    /*
     * BUG: recv() can write up to 256 bytes into a 64-byte buffer.
     * No bounds check. Excess bytes overwrite the saved frame pointer
     * and return address on the stack.
     */
    int bytes = recv(client_fd, buf, sizeof(buf) - 1, 0);
    if (bytes <= 0) {
        close(client_fd);
        return;
    }

    buf[bytes] = '\0';

    if (bytes > 64) {
        const char *error = "Request too large\n";
        send(client_fd, error, strlen(error), 0);
        close(client_fd);
        return;
    }

    /* Echo back — lets attacker confirm delivery */
    snprintf(response, sizeof(response), "ACK: %s\n", buf);
    send(client_fd, response, strlen(response), 0);

    close(client_fd);
}

/* ------------------------------------------------------------------ */
/* Secret function — never called legitimately.                         */
/* Gaining control of the instruction pointer and redirecting here is   */
/* the win condition for the exercise.                                  */
/* ------------------------------------------------------------------ */
void secret_shell() {
    printf("[!] Buffer overflow successful — you have shell!\n");
    fflush(stdout);
    /* In a real scenario this would be: execve("/bin/sh", ...) */
    system("/bin/sh");
}

/* ------------------------------------------------------------------ */
/* Main — simple single-threaded accept loop                            */
/* ------------------------------------------------------------------ */
int main() {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen"); exit(1);
    }

    printf("[*] vuln_service listening on port %d\n", PORT);
    printf("[*] secret_shell() is at address: %p\n", secret_shell); /* helpful for lab */
    fflush(stdout);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len);
        if (client_fd < 0) { perror("accept"); continue; }
        printf("[*] Connection from %s\n", inet_ntoa(addr.sin_addr));
        fflush(stdout);
        handle_client(client_fd);
    }

    close(server_fd);
    return 0;
}
