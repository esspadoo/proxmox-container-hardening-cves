#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT 8080
#define BACKLOG 16

static void write_all(int fd, const char *s) {
    size_t left = strlen(s);
    while (left > 0) {
        ssize_t n = write(fd, s, left);
        if (n <= 0) return;
        s += n;
        left -= (size_t)n;
    }
}

static void write_bytes(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0) return;
        buf += n;
        len -= (size_t)n;
    }
}

static void append_log(const char *msg) {
    int fd = open("/var/log/docviewd/access.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    dprintf(fd, "%s\n", msg);
    close(fd);
}

static void write_pid_file(void) {
    int fd = open("/run/docviewd/docviewd.pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("pidfile");
        return;
    }
    dprintf(fd, "%ld\n", (long)getpid());
    close(fd);
}

static void print_current_label(void) {
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd < 0) {
        printf("label: unavailable (%s)\n", strerror(errno));
        return;
    }

    char label[512];
    ssize_t n = read(fd, label, sizeof(label) - 1);
    close(fd);
    if (n < 0) {
        printf("label: unreadable (%s)\n", strerror(errno));
        return;
    }

    label[n] = '\0';
    printf("label: %s", label);
    if (n == 0 || label[n - 1] != '\n') {
        putchar('\n');
    }
}

static int probe_read(const char *name, const char *path, int expect_success) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char buf[16];
        ssize_t n = read(fd, buf, sizeof(buf));
        int read_errno = errno;
        close(fd);

        if (expect_success && n >= 0) {
            printf("PASS %s: read %s\n", name, path);
            return 0;
        }

        if (expect_success) {
            printf("FAIL %s: read(%s) failed with %s\n", name, path, strerror(read_errno));
            return 1;
        }

        printf("FAIL %s: read %s succeeded; profile is probably complain or unconfined\n",
               name, path);
        return 1;
    }

    if (!expect_success && (errno == EACCES || errno == EPERM)) {
        printf("PASS %s: denied %s (%s)\n", name, path, strerror(errno));
        return 0;
    }

    printf("FAIL %s: open(%s) failed with %s\n", name, path, strerror(errno));
    return 1;
}

static int run_self_test(void) {
    int failures = 0;

    puts("docviewd AppArmor self-test");
    print_current_label();

    failures += probe_read("allowed-read", "/srv/docview/public/index.html", 1);
    failures += probe_read("denied-read", "/srv/docview/secret.txt", 0);

    if (failures == 0) {
        puts("result: PASS");
        return 0;
    }

    puts("result: FAIL");
    return 1;
}

static void send_text(int client, int code, const char *status, const char *body) {
    dprintf(client,
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            code, status, strlen(body), body);
}

static void send_file(int client, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "open(%s) failed: %s\n", path, strerror(errno));
        send_text(client, 500, "Internal Server Error", buf);
        return;
    }

    char body[8192];
    ssize_t n = read(fd, body, sizeof(body) - 1);
    close(fd);

    if (n < 0) {
        send_text(client, 500, "Internal Server Error", "read failed\n");
        return;
    }

    body[n] = '\0';
    dprintf(client,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %zd\r\n"
            "Connection: close\r\n"
            "\r\n",
            n);
    write_bytes(client, body, (size_t)n);
}

static void handle_client(int client) {
    char req[2048];
    ssize_t n = read(client, req, sizeof(req) - 1);
    if (n <= 0) return;
    req[n] = '\0';

    char method[16] = {0};
    char path[512] = {0};
    sscanf(req, "%15s %511s", method, path);

    char logline[700];
    snprintf(logline, sizeof(logline), "%s %s", method, path);
    append_log(logline);

    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        send_file(client, "/srv/docview/public/index.html");
        return;
    }

    if (strcmp(path, "/status") == 0) {
        int fd = open("/proc/self/attr/current", O_RDONLY);
        if (fd < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "cannot read AppArmor label: %s\n", strerror(errno));
            send_text(client, 500, "Internal Server Error", buf);
            return;
        }
        char label[512];
        ssize_t r = read(fd, label, sizeof(label) - 1);
        close(fd);
        if (r < 0) r = 0;
        label[r] = '\0';
        send_text(client, 200, "OK", label);
        return;
    }

    if (strcmp(path, "/forbidden-read") == 0) {
        int fd = open("/srv/docview/secret.txt", O_RDONLY);
        if (fd < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "blocked or failed as expected: %s\n", strerror(errno));
            send_text(client, 403, "Forbidden", buf);
            return;
        }
        close(fd);
        send_text(client, 200, "OK",
                  "unexpectedly read /srv/docview/secret.txt; this is allowed when the profile is unconfined or in complain mode\n");
        return;
    }

    if (strcmp(path, "/forbidden-write") == 0) {
        int fd = open("/tmp/forbidden.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "blocked or failed as expected: %s\n", strerror(errno));
            send_text(client, 403, "Forbidden", buf);
            return;
        }
        write_all(fd, "this should only work in complain mode\n");
        close(fd);
        send_text(client, 200, "OK",
                  "unexpectedly wrote /tmp/forbidden.txt; this is allowed when the profile is unconfined or in complain mode\n");
        return;
    }

    if (strcmp(path, "/forbidden-exec") == 0) {
        int rc = system("/bin/sh -c 'echo shell-exec-ok >/dev/null'");
        if (rc == -1) {
            char buf[256];
            snprintf(buf, sizeof(buf), "blocked or failed as expected: %s\n", strerror(errno));
            send_text(client, 403, "Forbidden", buf);
            return;
        }
        if (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) {
            send_text(client, 200, "OK",
                      "unexpectedly executed /bin/sh; this is allowed when the profile is unconfined or in complain mode\n");
        } else {
            send_text(client, 403, "Forbidden", "shell execution failed; likely blocked in enforce mode\n");
        }
        return;
    }

    send_text(client, 404, "Not Found",
              "Routes:\n"
              "  /\n"
              "  /status\n"
              "  /forbidden-read\n"
              "  /forbidden-write\n"
              "  /forbidden-exec\n");
}

static int make_server_socket(void) {
    const char *bind_addr = getenv("DOCVIEW_BIND");
    if (!bind_addr || !*bind_addr) bind_addr = "127.0.0.1";

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        exit(1);
    }

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid DOCVIEW_BIND address: %s\n", bind_addr);
        exit(1);
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(s, BACKLOG) < 0) {
        perror("listen");
        exit(1);
    }

    fprintf(stderr, "docviewd listening on %s:%d\n", bind_addr, PORT);
    return s;
}

static volatile sig_atomic_t stop = 0;
static void on_signal(int sig) {
    (void)sig;
    stop = 1;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        return run_self_test();
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    write_pid_file();
    append_log("docviewd started");

    int s = make_server_socket();

    while (!stop) {
        int client = accept(s, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        handle_client(client);
        close(client);
    }

    close(s);
    append_log("docviewd stopped");
    return 0;
}
