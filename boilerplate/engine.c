#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    char log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag, const char *value, unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }
    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }
    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req, int argc, char *argv[], int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' || nice_value < -20 || nice_value > 19) {
                fprintf(stderr, "Invalid value for --nice (expected -20..19): %s\n", argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);
    }
    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }
    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;
    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == 0 && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
    }
    if (buffer->shutting_down && buffer->count == 0) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }
    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;
    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    int log_fd;
    char log_file[PATH_MAX];

    while (1) {
        if (bounded_buffer_pop(&ctx->log_buffer, &item) != 0)
            break;

        snprintf(log_file, sizeof(log_file), "%s/%s.log", LOG_DIR, item.container_id);
        log_fd = open(log_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd < 0) {
            perror("open log file");
            continue;
        }

        if (write(log_fd, item.data, item.length) < 0)
            perror("write to log");

        close(log_fd);
    }

    return NULL;
}

int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;
    char *shell_argv[] = {"/bin/sh", "-c", cfg->command, NULL};
    char proc_path[PATH_MAX];

    if (dup2(cfg->log_write_fd, STDOUT_FILENO) < 0 || dup2(cfg->log_write_fd, STDERR_FILENO) < 0) {
        perror("dup2");
        return 1;
    }
    close(cfg->log_write_fd);

    if (cfg->nice_value != 0) {
        if (nice(cfg->nice_value) < 0)
            perror("nice");
    }

    snprintf(proc_path, sizeof(proc_path), "%s/proc", cfg->rootfs);
    if (mount("proc", proc_path, "proc", 0, NULL) < 0)
        perror("mount proc");

    if (chroot(cfg->rootfs) < 0) {
        perror("chroot");
        return 1;
    }

    if (chdir("/") < 0) {
        perror("chdir");
        return 1;
    }

    execvp(shell_argv[0], shell_argv);
    perror("execvp");
    return 1;
}

int register_with_monitor(int monitor_fd, const char *container_id, pid_t host_pid,
                          unsigned long soft_limit_bytes, unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

static supervisor_ctx_t *g_ctx = NULL;

static void sig_handler(int sig)
{
    (void)sig;
    if (g_ctx)
        g_ctx->should_stop = 1;
}

static container_record_t *find_container(supervisor_ctx_t *ctx, const char *id)
{
    container_record_t *c = ctx->containers;
    while (c) {
        if (strcmp(c->id, id) == 0)
            return c;
        c = c->next;
    }
    return NULL;
}

static void add_container(supervisor_ctx_t *ctx, container_record_t *c)
{
    c->next = ctx->containers;
    ctx->containers = c;
}

typedef struct {
    supervisor_ctx_t *ctx;
    int client_fd;
} client_thread_arg_t;

static void *client_thread_handler(void *arg)
{
    client_thread_arg_t *args = (client_thread_arg_t *)arg;
    supervisor_ctx_t *ctx = args->ctx;
    int client_fd = args->client_fd;
    control_request_t req;
    control_response_t resp;

    free(args);

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));

    if (read(client_fd, &req, sizeof(req)) <= 0) {
        close(client_fd);
        return NULL;
    }

    switch (req.kind) {
    case CMD_START:
    case CMD_RUN: {
        container_record_t *c;
        pid_t child_pid;
        int pipe_fds[2];
        child_config_t cfg;

        c = find_container(ctx, req.container_id);
        if (c) {
            resp.status = 1;
            snprintf(resp.message, sizeof(resp.message), "Container exists");
            break;
        }

        if (pipe(pipe_fds) < 0) {
            resp.status = 1;
            snprintf(resp.message, sizeof(resp.message), "pipe failed");
            break;
        }

        c = malloc(sizeof(*c));
        if (!c) {
            resp.status = 1;
            strncpy(resp.message, "malloc failed", sizeof(resp.message) - 1);
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            break;
        }

        memset(c, 0, sizeof(*c));
        strncpy(c->id, req.container_id, sizeof(c->id) - 1);
        c->started_at = time(NULL);
        c->state = CONTAINER_STARTING;
        c->soft_limit_bytes = req.soft_limit_bytes;
        c->hard_limit_bytes = req.hard_limit_bytes;
        snprintf(c->log_path, sizeof(c->log_path), "%s/%s.log", LOG_DIR, req.container_id);

        memset(&cfg, 0, sizeof(cfg));
        strncpy(cfg.id, req.container_id, sizeof(cfg.id) - 1);
        strncpy(cfg.rootfs, req.rootfs, sizeof(cfg.rootfs) - 1);
        strncpy(cfg.command, req.command, sizeof(cfg.command) - 1);
        cfg.nice_value = req.nice_value;
        cfg.log_write_fd = pipe_fds[1];

        void *stack = malloc(STACK_SIZE);
if (!stack) {
    perror("malloc");
    resp.status = 1;
    snprintf(resp.message, sizeof(resp.message), "malloc failed");
    free(c);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    break;
}

child_pid = clone(
    child_fn,
    (char *)stack + STACK_SIZE,
    CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD,
    &cfg
);

if (child_pid < 0) {
    perror("clone");   // VERY IMPORTANT (debug)
    resp.status = 1;
    snprintf(resp.message, sizeof(resp.message), "clone failed");
    free(stack);
    free(c);
    close(pipe_fds[0]);
    break;
}
close(pipe_fds[1]);

if (child_pid < 0) {
    resp.status = 1;
    snprintf(resp.message, sizeof(resp.message), "clone failed");
    free(c);
    close(pipe_fds[0]);
    break;
}

c->host_pid = child_pid;
c->state = CONTAINER_RUNNING;

pthread_mutex_lock(&ctx->metadata_lock);
add_container(ctx, c);
pthread_mutex_unlock(&ctx->metadata_lock);

if (register_with_monitor(ctx->monitor_fd, req.container_id, child_pid,
                         req.soft_limit_bytes, req.hard_limit_bytes) < 0) {
    fprintf(stderr, "register_with_monitor failed\n");
}

// --------- LOGGING FIX START ---------
char buffer[4096];
int log_fd = open(c->log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);

if (log_fd < 0) {
    perror("open log file");
} else {
    ssize_t n;
    while ((n = read(pipe_fds[0], buffer, sizeof(buffer))) > 0) {
        if (write(log_fd, buffer, n) < 0) {
            perror("write log");
            break;
        }
    }
    close(log_fd);
}

close(pipe_fds[0]);
// --------- LOGGING FIX END ---------

        if (req.kind == CMD_RUN) {
            int status;
            waitpid(child_pid, &status, 0);
            c->state = CONTAINER_EXITED;
            if (WIFEXITED(status))
                c->exit_code = WEXITSTATUS(status);
            snprintf(resp.message, sizeof(resp.message), "Container exited");
        } else {
            snprintf(resp.message, sizeof(resp.message), "Container started");
        }
        resp.status = 0;
        break;
    }
    case CMD_PS: {
        container_record_t *c;
        char buf[2048];
        int pos = 0;

        pthread_mutex_lock(&ctx->metadata_lock);
        c = ctx->containers;
        while (c && pos < (int)sizeof(buf) - 100) {
            int n = snprintf(buf + pos, sizeof(buf) - pos - 100,
                            "%s\t%d\t%s\n", c->id, c->host_pid,
                            state_to_string(c->state));
            if (n > 0)
                pos += n;
            c = c->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
        strncpy(resp.message, buf, sizeof(resp.message) - 1);
        resp.status = 0;
        break;
    }
    case CMD_LOGS: {
        container_record_t *c;
        FILE *f;
        char log_file[PATH_MAX];

        pthread_mutex_lock(&ctx->metadata_lock);
        c = find_container(ctx, req.container_id);
        if (!c) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            resp.status = 1;
            snprintf(resp.message, sizeof(resp.message), "Container not found");
            break;
        }
        strncpy(log_file, c->log_path, sizeof(log_file) - 1);
        pthread_mutex_unlock(&ctx->metadata_lock);

        f = fopen(log_file, "r");
        if (!f) {
            resp.status = 0;
            strncpy(resp.message, "(no logs)", sizeof(resp.message) - 1);
            break;
        }
        fread(resp.message, 1, sizeof(resp.message) - 1, f);
        fclose(f);
        resp.status = 0;
        break;
    }
    case CMD_STOP: {
        container_record_t *c;

        pthread_mutex_lock(&ctx->metadata_lock);
        c = find_container(ctx, req.container_id);
        if (!c) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            resp.status = 1;
            snprintf(resp.message, sizeof(resp.message), "Container not found");
            break;
        }
        kill(c->host_pid, SIGTERM);
        c->state = CONTAINER_STOPPED;
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message), "Stopped %s", req.container_id);
        break;
    }
    default:
        resp.status = 1;
        strncpy(resp.message, "Unsupported command", sizeof(resp.message) - 1);
    }

    write(client_fd, &resp, sizeof(resp));
    close(client_fd);
    return NULL;
}

static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct sockaddr_un addr;
    int rc, client_fd;
    struct sigaction sa;
    pthread_t client_t;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;
    g_ctx = &ctx;

    mkdir(LOG_DIR, 0755);

    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) {
        errno = rc;
        perror("pthread_mutex_init");
        return 1;
    }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc;
        perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0) {
        fprintf(stderr, "Warning: Cannot open /dev/container_monitor\n");
        ctx.monitor_fd = -1;
    }

    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) {
        perror("socket");
        goto cleanup;
    }

    unlink(CONTROL_PATH);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        goto cleanup;
    }

    chmod(CONTROL_PATH, 0666);

    if (listen(ctx.server_fd, 5) < 0) {
        perror("listen");
        goto cleanup;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    rc = pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);
    if (rc != 0) {
        errno = rc;
        perror("pthread_create");
        goto cleanup;
    }

    printf("[supervisor] Listening on %s\n", CONTROL_PATH);
    printf("[supervisor] Base rootfs: %s\n", rootfs);

    while (!ctx.should_stop) {
        client_fd = accept(ctx.server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            continue;
        }

        client_thread_arg_t *args = malloc(sizeof(*args));
        if (args) {
            args->ctx = &ctx;
            args->client_fd = client_fd;
            pthread_create(&client_t, NULL, client_thread_handler, args);
            pthread_detach(client_t);
        } else {
            close(client_fd);
        }
    }

cleanup:
    if (ctx.server_fd >= 0)
        close(ctx.server_fd);
    if (ctx.monitor_fd >= 0)
        close(ctx.monitor_fd);

    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);

    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);

    unlink(CONTROL_PATH);
    return 0;
}

static int send_control_request(const control_request_t *req)
{
    int sock;
    struct sockaddr_un addr;
    control_response_t resp;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    if (write(sock, req, sizeof(*req)) < 0) {
        perror("write request");
        close(sock);
        return 1;
    }

    memset(&resp, 0, sizeof(resp));
    if (read(sock, &resp, sizeof(resp)) < 0) {
        perror("read response");
        close(sock);
        return 1;
    }

    close(sock);

    if (resp.status != 0) {
        fprintf(stderr, "Supervisor error: %s\n", resp.message);
        return 1;
    }

    if (strlen(resp.message) > 0)
        printf("%s\n", resp.message);

    return 0;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr, "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr, "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;

    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
