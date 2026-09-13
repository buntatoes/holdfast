#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define HF_PATH_MAX 4096
#define HF_JSON_MAX 65536
#define HF_TIMEOUT_SEC 300
#define HF_MAX_ARGS 16
#define HF_ARG_MAX 256
#define HF_DEFAULT_SOCK "/tmp/holdfast.sock"
#define HF_ID_LEN 36

#ifdef open
#undef open
#endif
#ifdef open64
#undef open64
#endif
#ifdef fopen
#undef fopen
#endif
#ifdef fopen64
#undef fopen64
#endif
#ifdef creat
#undef creat
#endif

typedef int (*hf_open_fn)(const char *, int, mode_t);
typedef int (*hf_openat_fn)(int, const char *, int, mode_t);
typedef int (*hf_creat_fn)(const char *, mode_t);
typedef int (*hf_unlink_fn)(const char *);
typedef int (*hf_unlinkat_fn)(int, const char *, int);
typedef int (*hf_rename_fn)(const char *, const char *);
typedef int (*hf_renameat_fn)(int, const char *, int, const char *);
typedef FILE *(*hf_fopen_fn)(const char *, const char *);
typedef int (*hf_execve_fn)(const char *, char *const[], char *const[]);
typedef int (*hf_execv_fn)(const char *, char *const[]);
typedef int (*hf_execvp_fn)(const char *, char *const[]);
typedef int (*hf_execvpe_fn)(const char *, char *const[], char *const[]);
typedef int (*hf_execveat_fn)(int, const char *, char *const[], char *const[], int);
typedef int (*hf_connect_fn)(int, const struct sockaddr *, socklen_t);
typedef pid_t (*hf_fork_fn)(void);
typedef pid_t (*hf_vfork_fn)(void);
typedef int (*hf_socket_fn)(int, int, int);
typedef ssize_t (*hf_write_fn)(int, const void *, size_t);
typedef ssize_t (*hf_read_fn)(int, void *, size_t);
typedef int (*hf_close_fn)(int);
typedef int (*hf_setsockopt_fn)(int, int, int, const void *, socklen_t);
typedef int (*hf_getsockopt_fn)(int, int, int, void *, socklen_t *);
typedef ssize_t (*hf_send_fn)(int, const void *, size_t, int);

static hf_open_fn real_open;
static hf_open_fn real_open64;
static hf_openat_fn real_openat;
static hf_openat_fn real_openat64;
static hf_creat_fn real_creat;
static hf_unlink_fn real_unlink;
static hf_unlinkat_fn real_unlinkat;
static hf_rename_fn real_rename;
static hf_renameat_fn real_renameat;
static hf_fopen_fn real_fopen;
static hf_fopen_fn real_fopen64;
static hf_execve_fn real_execve;
static hf_execv_fn real_execv;
static hf_execvp_fn real_execvp;
static hf_execvpe_fn real_execvpe;
static hf_execveat_fn real_execveat;
static hf_connect_fn real_connect;
static hf_fork_fn real_fork;
static hf_vfork_fn real_vfork;
static hf_socket_fn real_socket;
static hf_write_fn real_write;
static hf_read_fn real_read;
static hf_close_fn real_close;
static hf_setsockopt_fn real_setsockopt;
static hf_getsockopt_fn real_getsockopt;
static hf_send_fn real_send;

static __thread int hf_busy;
static int hf_inited;

static void *hf_dlsym(const char *name) {
    return dlsym(RTLD_NEXT, name);
}

static void hf_ensure_init(void) {
    if (hf_inited)
        return;
    hf_busy++;
    real_open = (hf_open_fn)hf_dlsym("open");
    real_open64 = (hf_open_fn)hf_dlsym("open64");
    real_openat = (hf_openat_fn)hf_dlsym("openat");
    real_openat64 = (hf_openat_fn)hf_dlsym("openat64");
    real_creat = (hf_creat_fn)hf_dlsym("creat");
    real_unlink = (hf_unlink_fn)hf_dlsym("unlink");
    real_unlinkat = (hf_unlinkat_fn)hf_dlsym("unlinkat");
    real_rename = (hf_rename_fn)hf_dlsym("rename");
    real_renameat = (hf_renameat_fn)hf_dlsym("renameat");
    real_fopen = (hf_fopen_fn)hf_dlsym("fopen");
    real_fopen64 = (hf_fopen_fn)hf_dlsym("fopen64");
    real_execve = (hf_execve_fn)hf_dlsym("execve");
    real_execv = (hf_execv_fn)hf_dlsym("execv");
    real_execvp = (hf_execvp_fn)hf_dlsym("execvp");
    real_execvpe = (hf_execvpe_fn)hf_dlsym("execvpe");
    real_execveat = (hf_execveat_fn)hf_dlsym("execveat");
    real_connect = (hf_connect_fn)hf_dlsym("connect");
    real_fork = (hf_fork_fn)hf_dlsym("fork");
    real_vfork = (hf_vfork_fn)hf_dlsym("vfork");
    real_socket = (hf_socket_fn)hf_dlsym("socket");
    real_write = (hf_write_fn)hf_dlsym("write");
    real_read = (hf_read_fn)hf_dlsym("read");
    real_close = (hf_close_fn)hf_dlsym("close");
    real_setsockopt = (hf_setsockopt_fn)hf_dlsym("setsockopt");
    real_getsockopt = (hf_getsockopt_fn)hf_dlsym("getsockopt");
    real_send = (hf_send_fn)hf_dlsym("send");
    if (!real_open64)
        real_open64 = real_open;
    if (!real_openat64)
        real_openat64 = real_openat;
    if (!real_fopen64)
        real_fopen64 = real_fopen;
    hf_inited = 1;
    hf_busy--;
}

__attribute__((constructor)) static void hf_ctor(void) {
    hf_ensure_init();
}

static const char *hf_sock_path(void) {
    const char *p = getenv("HOLDFAST_SOCK");
    if (p && p[0])
        return p;
    return HF_DEFAULT_SOCK;
}

static void hf_uuid_v4(char out[HF_ID_LEN + 1]) {
    unsigned char b[16];
    memset(b, 0, sizeof(b));
    if (getrandom(b, sizeof(b), 0) != (ssize_t)sizeof(b)) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        unsigned long mix = (unsigned long)ts.tv_sec ^ (unsigned long)ts.tv_nsec ^
                            (unsigned long)getpid() ^ (unsigned long)&ts;
        for (int i = 0; i < 16; i++) {
            mix = mix * 6364136223846793005ULL + (unsigned long)i;
            b[i] ^= (unsigned char)(mix >> ((i % 7) + 8));
        }
    }
    b[6] = (unsigned char)((b[6] & 0x0f) | 0x40);
    b[8] = (unsigned char)((b[8] & 0x3f) | 0x80);
    snprintf(out, HF_ID_LEN + 1,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
             b[12], b[13], b[14], b[15]);
}

static void hf_iso8601(char *out, size_t n) {
    struct timespec ts;
    struct tm tm;
    int ms;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (!gmtime_r(&ts.tv_sec, &tm)) {
        snprintf(out, n, "1970-01-01T00:00:00.000Z");
        return;
    }
    ms = (int)(ts.tv_nsec / 1000000L);
    if (ms < 0)
        ms = 0;
    if (ms > 999)
        ms = 999;
    snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900,
             tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

static int hf_needs_mode(int flags) {
    if (flags & O_CREAT)
        return 1;
#ifdef O_TMPFILE
    if ((flags & O_TMPFILE) == O_TMPFILE)
        return 1;
#endif
    return 0;
}

static const char *hf_open_flags(int flags) {
    int acc = flags & O_ACCMODE;
    int writing = (acc == O_WRONLY || acc == O_RDWR || (flags & O_CREAT) ||
                   (flags & O_TRUNC));
#ifdef O_TMPFILE
    if ((flags & O_TMPFILE) == O_TMPFILE)
        writing = 1;
#endif
    if (!writing)
        return "r";
    if (acc == O_RDWR)
        return "rw";
    if (acc == O_WRONLY)
        return "w";
    return "w";
}

static const char *hf_fopen_flags(const char *mode) {
    int plus = 0;
    char m0;
    if (!mode || !mode[0])
        return "r";
    m0 = mode[0];
    for (const char *p = mode; *p; p++) {
        if (*p == '+')
            plus = 1;
    }
    if (m0 == 'r' && !plus)
        return "r";
    if (plus)
        return "rw";
    return "w";
}

static void hf_abs_join(char *out, size_t outsz, const char *dir, const char *rel) {
    size_t n = strlen(dir);
    if (n > 0 && dir[n - 1] == '/')
        snprintf(out, outsz, "%s%s", dir, rel);
    else
        snprintf(out, outsz, "%s/%s", dir, rel);
}

static void hf_abs_path(const char *path, char *out, size_t outsz) {
    char cwd[HF_PATH_MAX];
    if (!path || !path[0]) {
        snprintf(out, outsz, "%s", path ? path : "");
        return;
    }
    if (path[0] == '/') {
        snprintf(out, outsz, "%s", path);
        return;
    }
    if (!getcwd(cwd, sizeof(cwd))) {
        snprintf(out, outsz, "%s", path);
        return;
    }
    hf_abs_join(out, outsz, cwd, path);
}

static void hf_abs_path_at(int dirfd, const char *path, char *out, size_t outsz) {
    char dir[HF_PATH_MAX];
    if (!path || !path[0]) {
        snprintf(out, outsz, "%s", path ? path : "");
        return;
    }
    if (path[0] == '/') {
        snprintf(out, outsz, "%s", path);
        return;
    }
    if (dirfd == AT_FDCWD) {
        hf_abs_path(path, out, outsz);
        return;
    }
    {
        char linkp[64];
        ssize_t n;
        snprintf(linkp, sizeof(linkp), "/proc/self/fd/%d", dirfd);
        n = readlink(linkp, dir, sizeof(dir) - 1);
        if (n < 0) {
            hf_abs_path(path, out, outsz);
            return;
        }
        dir[n] = '\0';
        hf_abs_join(out, outsz, dir, path);
    }
}

static int hf_same_path(const char *a, const char *b) {
    char aa[HF_PATH_MAX], bb[HF_PATH_MAX];
    if (!a || !b)
        return 0;
    if (strcmp(a, b) == 0)
        return 1;
    hf_abs_path(a, aa, sizeof(aa));
    hf_abs_path(b, bb, sizeof(bb));
    return strcmp(aa, bb) == 0;
}

static int hf_is_holdfast_sock_path(const char *path) {
    int same;
    hf_busy++;
    same = hf_same_path(path, hf_sock_path());
    hf_busy--;
    return same;
}

static void hf_resolve_exe(char *out, size_t outsz) {
    ssize_t n = readlink("/proc/self/exe", out, outsz - 1);
    if (n < 0) {
        out[0] = '\0';
        return;
    }
    out[n] = '\0';
}

static int hf_json_unescape_char(const char **pp) {
    const char *p = *pp;
    char c = *p++;
    switch (c) {
    case '"':
    case '\\':
    case '/':
        *pp = p;
        return (unsigned char)c;
    case 'n':
        *pp = p;
        return '\n';
    case 'r':
        *pp = p;
        return '\r';
    case 't':
        *pp = p;
        return '\t';
    default:
        *pp = p;
        return (unsigned char)c;
    }
}

static int hf_json_str(const char *json, const char *key, char *out, size_t outsz) {
    char pat[80];
    const char *p;
    size_t i = 0;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(json, pat);
    if (!p)
        return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    if (*p != ':')
        return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    if (*p != '"')
        return -1;
    p++;
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\' && p[1]) {
            p++;
            out[i++] = (char)hf_json_unescape_char(&p);
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = '\0';
    return (*p == '"') ? 0 : -1;
}

typedef struct {
    char *p;
    char *end;
    int overflow;
} hf_buf;

static void hf_buf_init(hf_buf *b, char *mem, size_t n) {
    b->p = mem;
    b->end = mem + n;
    b->overflow = 0;
    if (n)
        mem[0] = '\0';
}

static void hf_put_raw(hf_buf *b, const char *s, size_t n) {
    if (b->overflow)
        return;
    if (b->p + n + 1 >= b->end) {
        b->overflow = 1;
        return;
    }
    memcpy(b->p, s, n);
    b->p += n;
    *b->p = '\0';
}

static void hf_puts(hf_buf *b, const char *s) {
    hf_put_raw(b, s, strlen(s));
}

static void hf_put_esc(hf_buf *b, const char *s) {
    static const char hex[] = "0123456789abcdef";
    if (!s)
        s = "";
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        char tmp[8];
        size_t n;
        if (c == '"' || c == '\\') {
            tmp[0] = '\\';
            tmp[1] = (char)c;
            n = 2;
        } else if (c == '\n') {
            tmp[0] = '\\';
            tmp[1] = 'n';
            n = 2;
        } else if (c == '\r') {
            tmp[0] = '\\';
            tmp[1] = 'r';
            n = 2;
        } else if (c == '\t') {
            tmp[0] = '\\';
            tmp[1] = 't';
            n = 2;
        } else if (c < 0x20) {
            tmp[0] = '\\';
            tmp[1] = 'u';
            tmp[2] = '0';
            tmp[3] = '0';
            tmp[4] = hex[(c >> 4) & 0xf];
            tmp[5] = hex[c & 0xf];
            n = 6;
        } else {
            tmp[0] = (char)c;
            n = 1;
        }
        hf_put_raw(b, tmp, n);
    }
}

static ssize_t hf_write_all(int fd, const char *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w;
        if (real_send)
            w = real_send(fd, buf + off, n - off, MSG_NOSIGNAL);
        else
            w = real_write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (w == 0)
            return -1;
        off += (size_t)w;
    }
    return (ssize_t)off;
}

static int hf_read_line(int fd, char *buf, size_t buflen) {
    size_t n = 0;
    while (n + 1 < buflen) {
        ssize_t r = real_read(fd, buf + n, 1);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1;
        if (buf[n] == '\n') {
            buf[n] = '\0';
            if (n > 0 && buf[n - 1] == '\r')
                buf[n - 1] = '\0';
            return 0;
        }
        n++;
    }
    return -1;
}

static int hf_ask(const char *kind, const char *op, const char *detail_obj) {
    char id[HF_ID_LEN + 1];
    char ts[64];
    char exe[HF_PATH_MAX];
    char cwd[HF_PATH_MAX];
    char req[HF_JSON_MAX];
    char resp[8192];
    char rid[HF_ID_LEN + 8];
    char decision[32];
    hf_buf b;
    const char *session;
    const char *sock_path;
    struct sockaddr_un un;
    struct timeval tv;
    int fd = -1;
    int ok = 0;
    size_t un_len;

    hf_busy++;

    sock_path = hf_sock_path();
    if (!sock_path || !sock_path[0] || !real_socket || !real_connect || !real_read ||
        !real_close || (!real_write && !real_send))
        goto out;

    hf_uuid_v4(id);
    hf_iso8601(ts, sizeof(ts));
    hf_resolve_exe(exe, sizeof(exe));
    if (!getcwd(cwd, sizeof(cwd)))
        cwd[0] = '\0';
    session = getenv("HOLDFAST_SESSION");
    if (!session)
        session = "";

    hf_buf_init(&b, req, sizeof(req));
    hf_puts(&b, "{\"id\":\"");
    hf_put_esc(&b, id);
    hf_puts(&b, "\",\"session\":\"");
    hf_put_esc(&b, session);
    hf_puts(&b, "\",\"kind\":\"");
    hf_put_esc(&b, kind);
    hf_puts(&b, "\",\"op\":\"");
    hf_put_esc(&b, op);
    hf_puts(&b, "\",\"pid\":");
    {
        char num[32];
        snprintf(num, sizeof(num), "%d", (int)getpid());
        hf_puts(&b, num);
    }
    hf_puts(&b, ",\"ppid\":");
    {
        char num[32];
        snprintf(num, sizeof(num), "%d", (int)getppid());
        hf_puts(&b, num);
    }
    hf_puts(&b, ",\"exe\":\"");
    hf_put_esc(&b, exe);
    hf_puts(&b, "\",\"cwd\":\"");
    hf_put_esc(&b, cwd);
    hf_puts(&b, "\",\"detail\":");
    hf_puts(&b, detail_obj ? detail_obj : "{}");
    hf_puts(&b, ",\"ts\":\"");
    hf_put_esc(&b, ts);
    hf_puts(&b, "\"}\n");
    if (b.overflow)
        goto out;

    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof(un.sun_path))
        goto out;
    memcpy(un.sun_path, sock_path, strlen(sock_path) + 1);
    un_len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path) + 1;

    fd = real_socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        fd = real_socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        goto out;

    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = HF_TIMEOUT_SEC;
    if (real_setsockopt) {
        real_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        real_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    if (real_connect(fd, (struct sockaddr *)&un, (socklen_t)un_len) < 0)
        goto out;

    if (hf_write_all(fd, req, strlen(req)) < 0)
        goto out;

    if (hf_read_line(fd, resp, sizeof(resp)) < 0)
        goto out;

    if (hf_json_str(resp, "id", rid, sizeof(rid)) != 0 || strcmp(rid, id) != 0)
        goto out;
    if (hf_json_str(resp, "decision", decision, sizeof(decision)) != 0)
        goto out;
    if (strcmp(decision, "allow") == 0)
        ok = 1;

out:
    if (fd >= 0)
        real_close(fd);
    hf_busy--;
    return ok;
}

static int hf_ask_file(const char *op, const char *path, const char *flags, unsigned mode) {
    char abs[HF_PATH_MAX];
    char detail[HF_PATH_MAX * 2 + 64];
    hf_buf b;

    hf_busy++;
    hf_abs_path(path, abs, sizeof(abs));
    hf_busy--;
    hf_buf_init(&b, detail, sizeof(detail));
    hf_puts(&b, "{\"path\":\"");
    hf_put_esc(&b, abs);
    hf_puts(&b, "\",\"flags\":\"");
    hf_put_esc(&b, flags ? flags : "r");
    hf_puts(&b, "\",\"mode\":");
    {
        char num[32];
        snprintf(num, sizeof(num), "%u", mode);
        hf_puts(&b, num);
    }
    hf_puts(&b, "}");
    if (b.overflow)
        return 0;
    return hf_ask("file", op, detail);
}

static int hf_ask_file_at(const char *op, int dirfd, const char *path, const char *flags,
                          unsigned mode) {
    char abs[HF_PATH_MAX];
    char detail[HF_PATH_MAX * 2 + 64];
    hf_buf b;

    hf_busy++;
    hf_abs_path_at(dirfd, path, abs, sizeof(abs));
    hf_busy--;
    hf_buf_init(&b, detail, sizeof(detail));
    hf_puts(&b, "{\"path\":\"");
    hf_put_esc(&b, abs);
    hf_puts(&b, "\",\"flags\":\"");
    hf_put_esc(&b, flags ? flags : "r");
    hf_puts(&b, "\",\"mode\":");
    {
        char num[32];
        snprintf(num, sizeof(num), "%u", mode);
        hf_puts(&b, num);
    }
    hf_puts(&b, "}");
    if (b.overflow)
        return 0;
    return hf_ask("file", op, detail);
}

static void hf_trunc_arg(char *dst, size_t dstsz, const char *src) {
    size_t n;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    n = strlen(src);
    if (n >= dstsz)
        n = dstsz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void hf_resolve_cmd(const char *file, int use_path, char *out, size_t outsz) {
    const char *pathenv;
    char dir[HF_PATH_MAX];
    char tmp[HF_PATH_MAX];
    if (!file || !file[0]) {
        out[0] = '\0';
        return;
    }
    if (!use_path || strchr(file, '/')) {
        hf_abs_path(file, out, outsz);
        return;
    }
    pathenv = getenv("PATH");
    if (!pathenv || !pathenv[0])
        pathenv = "/usr/local/bin:/usr/bin:/bin";
    while (*pathenv) {
        const char *colon = strchr(pathenv, ':');
        size_t n = colon ? (size_t)(colon - pathenv) : strlen(pathenv);
        if (n >= sizeof(dir))
            n = sizeof(dir) - 1;
        if (n == 0) {
            snprintf(dir, sizeof(dir), ".");
        } else {
            memcpy(dir, pathenv, n);
            dir[n] = '\0';
        }
        hf_abs_join(tmp, sizeof(tmp), dir, file);
        if (tmp[0] && access(tmp, X_OK) == 0) {
            if (tmp[0] == '/')
                snprintf(out, outsz, "%s", tmp);
            else
                hf_abs_path(tmp, out, outsz);
            return;
        }
        if (!colon)
            break;
        pathenv = colon + 1;
    }
    hf_abs_path(file, out, outsz);
}

static int hf_ask_exec(const char *file, char *const argv[], int use_path) {
    char resolved[HF_PATH_MAX];
    char detail[HF_JSON_MAX / 2];
    hf_buf b;
    int i;

    hf_busy++;
    hf_resolve_cmd(file, use_path, resolved, sizeof(resolved));
    hf_busy--;
    hf_buf_init(&b, detail, sizeof(detail));
    hf_puts(&b, "{\"argv\":[");
    for (i = 0; argv && argv[i] && i < HF_MAX_ARGS; i++) {
        char arg[HF_ARG_MAX];
        if (i)
            hf_puts(&b, ",");
        hf_puts(&b, "\"");
        hf_trunc_arg(arg, sizeof(arg), argv[i]);
        hf_put_esc(&b, arg);
        hf_puts(&b, "\"");
    }
    hf_puts(&b, "],\"resolved\":\"");
    hf_put_esc(&b, resolved);
    hf_puts(&b, "\"}");
    if (b.overflow)
        return 0;
    return hf_ask("shell", "exec", detail);
}

static const char *hf_net_family(int sockfd) {
    int t = 0;
    socklen_t l = sizeof(t);
    if (real_getsockopt && real_getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &t, &l) == 0) {
        if (t == SOCK_DGRAM)
            return "udp";
        if (t == SOCK_STREAM)
            return "tcp";
    }
    return "tcp";
}

static int hf_unix_sun_path(const struct sockaddr_un *un, socklen_t addrlen, char *out,
                            size_t outsz) {
    size_t n;
    if (addrlen < offsetof(struct sockaddr_un, sun_path) + 1) {
        out[0] = '\0';
        return -1;
    }
    n = (size_t)addrlen - offsetof(struct sockaddr_un, sun_path);
    if (n > sizeof(un->sun_path))
        n = sizeof(un->sun_path);
    if (n == 0) {
        out[0] = '\0';
        return -1;
    }
    if (un->sun_path[0] == '\0') {
        /* abstract namespace */
        size_t rest = n > 1 ? n - 1 : 0;
        if (rest >= outsz - 6)
            rest = outsz - 7;
        memcpy(out, "unix:@", 6);
        memcpy(out + 6, un->sun_path + 1, rest);
        out[6 + rest] = '\0';
        return 1;
    }
    {
        char tmp[sizeof(un->sun_path) + 1];
        memcpy(tmp, un->sun_path, n);
        tmp[n] = '\0';
        /* ensure C string even if addrlen did not include NUL */
        tmp[sizeof(tmp) - 1] = '\0';
        snprintf(out, outsz, "%s", tmp);
        return 0;
    }
}

static int hf_ask_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char host[HF_PATH_MAX + 16];
    char detail[HF_PATH_MAX + 128];
    hf_buf b;
    unsigned port = 0;
    const char *family = "tcp";
    sa_family_t af;

    if (!addr || addrlen < sizeof(sa_family_t))
        return 1;

    af = addr->sa_family;
    if (af == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
        char sunp[sizeof(un->sun_path) + 8];
        int kind = hf_unix_sun_path(un, addrlen, sunp, sizeof(sunp));
        if (kind == 0 && hf_is_holdfast_sock_path(sunp))
            return 1;
        family = "unix";
        port = 0;
        if (kind == 1)
            snprintf(host, sizeof(host), "%s", sunp);
        else {
            char abs[HF_PATH_MAX];
            hf_abs_path(sunp, abs, sizeof(abs));
            snprintf(host, sizeof(host), "unix:%s", abs);
        }
    } else if (af == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        if (addrlen < sizeof(*in))
            return 0;
        if (!inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host)))
            snprintf(host, sizeof(host), "0.0.0.0");
        port = ntohs(in->sin_port);
        family = hf_net_family(sockfd);
    } else if (af == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        if (addrlen < sizeof(*in6))
            return 0;
        if (!inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host)))
            snprintf(host, sizeof(host), "::");
        port = ntohs(in6->sin6_port);
        family = hf_net_family(sockfd);
    } else {
        snprintf(host, sizeof(host), "family:%d", (int)af);
        port = 0;
        family = "other";
    }

    hf_buf_init(&b, detail, sizeof(detail));
    hf_puts(&b, "{\"host\":\"");
    hf_put_esc(&b, host);
    hf_puts(&b, "\",\"port\":");
    {
        char num[32];
        snprintf(num, sizeof(num), "%u", port);
        hf_puts(&b, num);
    }
    hf_puts(&b, ",\"family\":\"");
    hf_put_esc(&b, family);
    hf_puts(&b, "\"}");
    if (b.overflow)
        return 0;
    return hf_ask("net", "connect", detail);
}

static void hf_deny(void) {
    errno = EPERM;
}

static mode_t hf_va_mode(int flags, va_list ap) {
    if (hf_needs_mode(flags))
        return (mode_t)va_arg(ap, int);
    return 0;
}

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    va_list ap;
    int r;

    hf_ensure_init();
    va_start(ap, flags);
    mode = hf_va_mode(flags, ap);
    va_end(ap);

    if (!real_open) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_open(pathname, flags, mode);
    if (hf_is_holdfast_sock_path(pathname))
        return real_open(pathname, flags, mode);
    if (!hf_ask_file("open", pathname, hf_open_flags(flags), (unsigned)mode)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    r = real_open(pathname, flags, mode);
    hf_busy--;
    return r;
}

int open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    va_list ap;
    int r;

    hf_ensure_init();
    va_start(ap, flags);
    mode = hf_va_mode(flags, ap);
    va_end(ap);

    if (!real_open64) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_open64(pathname, flags, mode);
    if (hf_is_holdfast_sock_path(pathname))
        return real_open64(pathname, flags, mode);
    if (!hf_ask_file("open", pathname, hf_open_flags(flags), (unsigned)mode)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    r = real_open64(pathname, flags, mode);
    hf_busy--;
    return r;
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    va_list ap;
    int r;
    char abs[HF_PATH_MAX];

    hf_ensure_init();
    va_start(ap, flags);
    mode = hf_va_mode(flags, ap);
    va_end(ap);

    if (!real_openat) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_openat(dirfd, pathname, flags, mode);
    hf_busy++;
    hf_abs_path_at(dirfd, pathname, abs, sizeof(abs));
    hf_busy--;
    if (hf_is_holdfast_sock_path(pathname) || hf_is_holdfast_sock_path(abs))
        return real_openat(dirfd, pathname, flags, mode);
    if (!hf_ask_file_at("open", dirfd, pathname, hf_open_flags(flags), (unsigned)mode)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    r = real_openat(dirfd, pathname, flags, mode);
    hf_busy--;
    return r;
}

int openat64(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    va_list ap;
    int r;
    char abs[HF_PATH_MAX];

    hf_ensure_init();
    va_start(ap, flags);
    mode = hf_va_mode(flags, ap);
    va_end(ap);

    if (!real_openat64) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_openat64(dirfd, pathname, flags, mode);
    hf_busy++;
    hf_abs_path_at(dirfd, pathname, abs, sizeof(abs));
    hf_busy--;
    if (hf_is_holdfast_sock_path(pathname) || hf_is_holdfast_sock_path(abs))
        return real_openat64(dirfd, pathname, flags, mode);
    if (!hf_ask_file_at("open", dirfd, pathname, hf_open_flags(flags), (unsigned)mode)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    r = real_openat64(dirfd, pathname, flags, mode);
    hf_busy--;
    return r;
}

int creat(const char *pathname, mode_t mode) {
    int r;

    hf_ensure_init();
    if (!real_creat) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_creat(pathname, mode);
    if (hf_is_holdfast_sock_path(pathname))
        return real_creat(pathname, mode);
    if (!hf_ask_file("creat", pathname, "w", (unsigned)mode)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    r = real_creat(pathname, mode);
    hf_busy--;
    return r;
}

int unlink(const char *pathname) {
    int r;

    hf_ensure_init();
    if (!real_unlink) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_unlink(pathname);
    if (!hf_ask_file("unlink", pathname, "w", 0)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    r = real_unlink(pathname);
    hf_busy--;
    return r;
}

int unlinkat(int dirfd, const char *pathname, int flags) {
    int r;

    hf_ensure_init();
    if (!real_unlinkat) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_unlinkat(dirfd, pathname, flags);
    if (!hf_ask_file_at("unlink", dirfd, pathname, "w", 0)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    r = real_unlinkat(dirfd, pathname, flags);
    hf_busy--;
    return r;
}

int rename(const char *oldpath, const char *newpath) {
    int r;

    hf_ensure_init();
    if (!real_rename) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_rename(oldpath, newpath);
    /* Destination is the write target; op=rename tells the operator. */
    if (!hf_ask_file("rename", newpath, "w", 0)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    r = real_rename(oldpath, newpath);
    hf_busy--;
    return r;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    int r;

    hf_ensure_init();
    if (!real_renameat) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (!hf_ask_file_at("rename", newdirfd, newpath, "w", 0)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    r = real_renameat(olddirfd, oldpath, newdirfd, newpath);
    hf_busy--;
    return r;
}

FILE *fopen(const char *pathname, const char *mode) {
    FILE *fp;

    hf_ensure_init();
    if (!real_fopen) {
        hf_deny();
        return NULL;
    }
    if (hf_busy)
        return real_fopen(pathname, mode);
    if (hf_is_holdfast_sock_path(pathname))
        return real_fopen(pathname, mode);
    if (!hf_ask_file("open", pathname, hf_fopen_flags(mode), 0)) {
        hf_deny();
        return NULL;
    }
    hf_busy++;
    fp = real_fopen(pathname, mode);
    hf_busy--;
    return fp;
}

FILE *fopen64(const char *pathname, const char *mode) {
    FILE *fp;

    hf_ensure_init();
    if (!real_fopen64) {
        hf_deny();
        return NULL;
    }
    if (hf_busy)
        return real_fopen64(pathname, mode);
    if (hf_is_holdfast_sock_path(pathname))
        return real_fopen64(pathname, mode);
    if (!hf_ask_file("open", pathname, hf_fopen_flags(mode), 0)) {
        hf_deny();
        return NULL;
    }
    hf_busy++;
    fp = real_fopen64(pathname, mode);
    hf_busy--;
    return fp;
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    hf_ensure_init();
    if (!real_execve) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_execve(pathname, argv, envp);
    if (!hf_ask_exec(pathname, argv, 0)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    {
        int r = real_execve(pathname, argv, envp);
        hf_busy--;
        return r;
    }
}

int execv(const char *path, char *const argv[]) {
    hf_ensure_init();
    if (!real_execv) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_execv(path, argv);
    if (!hf_ask_exec(path, argv, 0)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    {
        int r = real_execv(path, argv);
        hf_busy--;
        return r;
    }
}

int execvp(const char *file, char *const argv[]) {
    hf_ensure_init();
    if (!real_execvp) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_execvp(file, argv);
    if (!hf_ask_exec(file, argv, 1)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    {
        int r = real_execvp(file, argv);
        hf_busy--;
        return r;
    }
}

int execvpe(const char *file, char *const argv[], char *const envp[]) {
    hf_ensure_init();
    if (!real_execvpe) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_execvpe(file, argv, envp);
    if (!hf_ask_exec(file, argv, 1)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    {
        int r = real_execvpe(file, argv, envp);
        hf_busy--;
        return r;
    }
}

int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags) {
    char resolved[HF_PATH_MAX];
    const char *ask_path;
    char pathbuf[HF_PATH_MAX];

    hf_ensure_init();
    if (!real_execveat) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_execveat(dirfd, pathname, argv, envp, flags);
    pathbuf[0] = '\0';
    snprintf(pathbuf, sizeof(pathbuf), "%s", pathname);
#ifdef AT_EMPTY_PATH
    if ((flags & AT_EMPTY_PATH) && pathbuf[0] == '\0') {
        snprintf(resolved, sizeof(resolved), "/proc/self/fd/%d", dirfd);
        ask_path = resolved;
    } else
#endif
    {
        hf_busy++;
        hf_abs_path_at(dirfd, pathbuf, resolved, sizeof(resolved));
        hf_busy--;
        ask_path = resolved[0] ? resolved : pathbuf;
    }
    if (!hf_ask_exec(ask_path, argv, 0)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    {
        int r = real_execveat(dirfd, pathname, argv, envp, flags);
        hf_busy--;
        return r;
    }
}

/*
 * glibc posix_spawn often vforks. The child shares VM with the parent until
 * exec, and its symbol binding can rewrite the parent's PLT — after which
 * connect() in the agent no longer hits this library. Use a real fork.
 */
pid_t vfork(void) {
    hf_ensure_init();
    if (real_fork)
        return real_fork();
    errno = ENOSYS;
    return (pid_t)-1;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int r;

    hf_ensure_init();
    if (!real_connect) {
        hf_deny();
        return -1;
    }
    if (hf_busy)
        return real_connect(sockfd, addr, addrlen);
    if (!hf_ask_connect(sockfd, addr, addrlen)) {
        hf_deny();
        return -1;
    }
    hf_busy++;
    r = real_connect(sockfd, addr, addrlen);
    hf_busy--;
    return r;
}
