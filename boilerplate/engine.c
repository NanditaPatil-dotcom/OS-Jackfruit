/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Intentionally partial starter:
 *   - command-line shape is defined
 *   - key runtime data structures are defined
 *   - bounded-buffer skeleton is defined
 *   - supervisor / client split is outlined
 *
 * Students are expected to design:
 *   - the control-plane IPC implementation
 *   - container lifecycle and metadata synchronization
 *   - clone + namespace setup for each container
 *   - producer/consumer behavior for log buffering
 *   - signal handling and graceful shutdown
 */

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

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
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

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
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
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
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

/*
 * TODO:
 * Implement producer-side insertion into the bounded buffer.
 *
 * Requirements:
 *   - block or fail according to your chosen policy when the buffer is full
 *   - wake consumers correctly
 *   - stop cleanly if shutdown begins
 */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    while (buffer->count >= LOG_BUFFER_CAPACITY) {
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);
        if (buffer->shutting_down) {
            pthread_mutex_unlock(&buffer->mutex);
            return -1;
        }
    }

    memcpy(&buffer->items[buffer->tail], item, sizeof(log_item_t));
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * TODO:
 * Implement consumer-side removal from the bounded buffer.
 *
 * Requirements:
 *   - wait correctly while the buffer is empty
 *   - return a useful status when shutdown is in progress
 *   - avoid races with producers and shutdown
 */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    while (buffer->count == 0 && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
    }

    if (buffer->count == 0) {
        pthread_mutex_unlock(&buffer->mutex);
        return 1;
    }

    memcpy(item, &buffer->items[buffer->head], sizeof(log_item_t));
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * TODO:
 * Implement the logging consumer thread.
 *
 * Suggested responsibilities:
 *   - remove log chunks from the bounded buffer
 *   - route each chunk to the correct per-container log file
 *   - exit cleanly when shutdown begins and pending work is drained
 */
void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    int fd;
    
    if (!ctx)
        return NULL;

    while (1) {
        if (bounded_buffer_pop(&ctx->log_buffer, &item) != 0) {
            break;
        }

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *rec = ctx->containers;
        while (rec) {
            if (strncmp(rec->id, item.container_id, CONTAINER_ID_LEN) == 0)
                break;
            rec = rec->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (!rec || !rec->log_path[0])
            continue;

        fd = open(rec->log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            write(fd, item.data, item.length);
            close(fd);
        }
    }

    return NULL;
}

/*
 * TODO:
 * Implement the clone child entrypoint.
 *
 * Required outcomes:
 *   - isolated PID / UTS / mount context
 *   - chroot or pivot_root into rootfs
 *   - working /proc inside container
 *   - stdout / stderr redirected to the supervisor logging path
 *   - configured command executed inside the container
 */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    if (!cfg)
        return 1;

    if (unshare(CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS) < 0)
        return 1;

    sethostname("container", 9);

    if (chroot(cfg->rootfs) < 0)
        return 1;
    
    if (chdir("/") < 0)
        return 1;

    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC, NULL) < 0)
        return 1;

    if (cfg->log_write_fd >= 0) {
        dup2(cfg->log_write_fd, STDOUT_FILENO);
        dup2(cfg->log_write_fd, STDERR_FILENO);
        if (cfg->log_write_fd != STDOUT_FILENO && 
            cfg->log_write_fd != STDERR_FILENO)
            close(cfg->log_write_fd);
    }

    if (cfg->nice_value != 0)
        nice(cfg->nice_value);

    execle("/bin/sh", "sh", "-c", cfg->command, NULL, NULL);
    return 1;
}

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
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

/*
 * TODO:
 * Implement the long-running supervisor process.
 *
 * Suggested responsibilities:
 *   - create and bind the control-plane IPC endpoint
 *   - initialize shared metadata and the bounded buffer
 *   - start the logging thread
 *   - accept control requests and update container state
 *   - reap children and respond to signals
 */
static supervisor_ctx_t *g_ctx = NULL;

static void sigchld_handler(int sig)
{
    (void)sig;
    if (g_ctx) {
        pid_t pid;
        int status;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            pthread_mutex_lock(&g_ctx->metadata_lock);
            container_record_t *rec = g_ctx->containers;
            while (rec) {
                if (rec->host_pid == pid) {
                    rec->state = WIFSIGNALED(status) ? CONTAINER_KILLED : CONTAINER_EXITED;
                    rec->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                    rec->exit_signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
                    break;
                }
                rec = rec->next;
            }
            pthread_mutex_unlock(&g_ctx->metadata_lock);
        }
    }
}

static void signal_handler(int sig)
{
    (void)sig;
    if (g_ctx) {
        g_ctx->should_stop = 1;
    }
}

static container_record_t *find_container(supervisor_ctx_t *ctx, const char *id)
{
    container_record_t *rec = ctx->containers;
    while (rec) {
        if (strncmp(rec->id, id, CONTAINER_ID_LEN) == 0)
            return rec;
        rec = rec->next;
    }
    return NULL;
}

static int add_container(supervisor_ctx_t *ctx, container_record_t *rec)
{
    rec->next = ctx->containers;
    ctx->containers = rec;
    return 0;
}

static int remove_container(supervisor_ctx_t *ctx, const char *id)
{
    container_record_t **p = &ctx->containers;
    while (*p) {
        if (strncmp((*p)->id, id, CONTAINER_ID_LEN) == 0) {
            container_record_t *tmp = *p;
            *p = tmp->next;
            free(tmp);
            return 0;
        }
        p = &(*p)->next;
    }
    return -1;
}

static int handle_client_request(supervisor_ctx_t *ctx, int client_fd)
{
    control_request_t req;
    control_response_t resp;
    ssize_t n;

    memset(&req, 0, sizeof(req));
    n = recv(client_fd, &req, sizeof(req), 0);
    if (n <= 0) {
        return -1;
    }

    memset(&resp, 0, sizeof(resp));

    switch (req.kind) {
    case CMD_START:
    case CMD_RUN: {
        container_record_t *rec = malloc(sizeof(container_record_t));
        if (!rec) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message), "Out of memory");
            break;
        }

        memset(rec, 0, sizeof(container_record_t));
        strncpy(rec->id, req.container_id, CONTAINER_ID_LEN - 1);
        rec->soft_limit_bytes = req.soft_limit_bytes;
        rec->hard_limit_bytes = req.hard_limit_bytes;
        rec->state = CONTAINER_STARTING;
        rec->started_at = time(NULL);

        snprintf(rec->log_path, sizeof(rec->log_path), 
                 LOG_DIR "/%s.log", req.container_id);
        mkdir(LOG_DIR, 0755);

        int log_fd = open(rec->log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (log_fd < 0) {
            free(rec);
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message), "Failed to create log file");
            break;
        }

        child_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        strncpy(cfg.id, req.container_id, CONTAINER_ID_LEN - 1);
        strncpy(cfg.rootfs, req.rootfs, sizeof(cfg.rootfs) - 1);
        strncpy(cfg.command, req.command, sizeof(cfg.command) - 1);
        cfg.nice_value = req.nice_value;
        cfg.log_write_fd = log_fd;

        char *stack = malloc(STACK_SIZE);
        if (!stack) {
            close(log_fd);
            free(rec);
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message), "Out of memory");
            break;
        }

        pid_t pid = clone(child_fn, stack + STACK_SIZE, 
                         SIGCHLD, &cfg);
        close(log_fd);
        free(stack);

        if (pid < 0) {
            free(rec);
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message), "Clone failed: %s", strerror(errno));
            break;
        }

        rec->host_pid = pid;
        rec->state = CONTAINER_RUNNING;

        if (ctx->monitor_fd >= 0) {
            register_with_monitor(ctx->monitor_fd, rec->id, pid,
                                  rec->soft_limit_bytes, rec->hard_limit_bytes);
        }

        pthread_mutex_lock(&ctx->metadata_lock);
        add_container(ctx, rec);
        pthread_mutex_unlock(&ctx->metadata_lock);

        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message), "Container started with PID %d", pid);
        break;
    }

    case CMD_PS: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *rec = ctx->containers;
        char buffer[4096];
        buffer[0] = '\0';
        char line[256];
        
        while (rec) {
            snprintf(line, sizeof(line), "%-32s %-10d %-10s\n",
                     rec->id, rec->host_pid, state_to_string(rec->state));
            strncat(buffer, line, sizeof(buffer) - strlen(buffer) - 1);
            rec = rec->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
        
        if (buffer[0])
            send(client_fd, buffer, strlen(buffer), 0);
        break;
    }

    case CMD_LOGS: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *rec = find_container(ctx, req.container_id);
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (!rec || !rec->log_path[0]) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message), "Container not found");
            break;
        }

        int fd = open(rec->log_path, O_RDONLY);
        if (fd < 0) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message), "Cannot open log file");
            break;
        }

        char logbuf[8192];
        ssize_t r;
        while ((r = read(fd, logbuf, sizeof(logbuf) - 1)) > 0) {
            send(client_fd, logbuf, r, 0);
        }
        close(fd);
        return 0;
    }

    case CMD_STOP: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *rec = find_container(ctx, req.container_id);
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (!rec) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message), "Container not found");
            break;
        }

        if (kill(rec->host_pid, SIGKILL) < 0) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message), "Failed to kill: %s", strerror(errno));
            break;
        }

        if (ctx->monitor_fd >= 0) {
            unregister_from_monitor(ctx->monitor_fd, rec->id, rec->host_pid);
        }

        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message), "Container stopped");
        break;
    }

    default:
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message), "Unknown command");
    }

    send(client_fd, &resp, sizeof(resp), 0);
    return 0;
}

static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    int rc;
    struct sigaction sa;

    (void)rootfs;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;
    g_ctx = &ctx;

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
        perror("Warning: cannot open /dev/container_monitor");
    }

    unlink(CONTROL_PATH);
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) {
        perror("socket");
        goto cleanup;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        goto cleanup;
    }

    if (listen(ctx.server_fd, 10) < 0) {
        perror("listen");
        goto cleanup;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx) != 0) {
        perror("pthread_create");
        goto cleanup;
    }

    while (!ctx.should_stop) {
        fd_set rfds;
        struct timeval tv;
        int maxfd = ctx.server_fd;
        
        FD_ZERO(&rfds);
        FD_SET(ctx.server_fd, &rfds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ready = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (ctx.should_stop)
                break;
            continue;
        }
        
        if (FD_ISSET(ctx.server_fd, &rfds)) {
            int client_fd = accept(ctx.server_fd, NULL, NULL);
            if (client_fd >= 0) {
                handle_client_request(&ctx, client_fd);
                close(client_fd);
            }
        }
    }

    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);

    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *rec = ctx.containers;
    while (rec) {
        if (rec->state == CONTAINER_RUNNING) {
            kill(rec->host_pid, SIGKILL);
            if (ctx.monitor_fd >= 0) {
                unregister_from_monitor(ctx.monitor_fd, rec->id, rec->host_pid);
            }
        }
        container_record_t *next = rec->next;
        free(rec);
        rec = next;
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

cleanup:
    if (ctx.monitor_fd >= 0)
        close(ctx.monitor_fd);
    if (ctx.server_fd >= 0) {
        close(ctx.server_fd);
        unlink(CONTROL_PATH);
    }
    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);
    g_ctx = NULL;
    return 0;
}

/*
 * TODO:
 * Implement the client-side control request path.
 *
 * The CLI commands should use a second IPC mechanism distinct from the
 * logging pipe. A UNIX domain socket is the most direct option, but a
 * FIFO or shared memory design is also acceptable if justified.
 */
static int send_control_request(const control_request_t *req)
{
    int sock_fd;
    struct sockaddr_un addr;
    control_response_t resp;
    ssize_t n;

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    printf("[CLI] Connecting to supervisor via IPC socket...\n");
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock_fd);
        return 1;
    }

    if (send(sock_fd, req, sizeof(*req), 0) < 0) {
        perror("send");
        close(sock_fd);
        return 1;
    }

    printf("[CLI] Sent command for container '%s'.\n", req->container_id);

    if (req->kind == CMD_PS || req->kind == CMD_LOGS) {
        char buffer[8192];
        ssize_t r;
        while ((r = recv(sock_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[r] = '\0';
            fputs(buffer, stdout);
        }
    } else {
        n = recv(sock_fd, &resp, sizeof(resp), 0);
        if (n > 0) {
            printf("[CLI] Response received: %s\n", resp.message);
            if (resp.status != 0) {
                fprintf(stderr, "Error: %s\n", resp.message);
            } else {
                printf("%s\n", resp.message);
            }
        }
    }

    close(sock_fd);
    return 0;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
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
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
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
