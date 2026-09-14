/*
 * Holdfast Jail — proprietary. Not Apache License 2.0.
 * Copyright 2026 Holdfast
 * See jail/LICENSE.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define HF_JAIL_VERSION "0.2.2"
#define HF_DEFAULT_SOCK "/tmp/holdfast.sock"
#define HF_MAX_BINDS 16
#define HF_MAX_FILTER 512

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

#define HF_FS_ABI1                                                                     \
    (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |                      \
     LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |                      \
     LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |                  \
     LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |                      \
     LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |                      \
     LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |                    \
     LANDLOCK_ACCESS_FS_MAKE_SYM)

#define HF_NS_FLAGS                                                                    \
    (CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP)

static const char *hf_ro_etc[] = {
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/localtime",
    "/etc/timezone",
    "/etc/alternatives",
    "/etc/os-release",
    "/etc/python3",
    "/etc/python3.12",
    "/etc/python3.13",
    "/etc/crypto-policies",
    NULL,
};

static const char *hf_dev_nodes[] = {
    "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty",
    NULL,
};

static const char *hf_usr_symlinks[] = {"/bin", "/sbin", "/lib", "/lib64", "/lib32",
                                        "/libx32", NULL};

typedef struct {
    char root[PATH_MAX];
    char sock[PATH_MAX];
    char preload[PATH_MAX];
    char session[256];
    char hostname[256];
    char cwd[PATH_MAX];
    char newroot[PATH_MAX];
    char *const *argv;
    char ro[HF_MAX_BINDS][PATH_MAX];
    char rw[HF_MAX_BINDS][PATH_MAX];
    int n_ro;
    int n_rw;
    int member;
    int net_none;
    int use_preload;
} hf_cfg;

static void die(int code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("holdfast-jail: ", stderr);
    vfprintf(stderr, fmt, ap);
    if (errno) {
        fprintf(stderr, ": %s", strerror(errno));
    }
    fputc('\n', stderr);
    va_end(ap);
    _exit(code);
}

static void warnx(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("holdfast-jail: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t n = strlen(data);
    ssize_t w = write(fd, data, n);
    int saved = errno;
    close(fd);
    errno = saved;
    return w == (ssize_t)n ? 0 : -1;
}

static int mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    size_t len;
    if (!path || !path[0]) {
        errno = EINVAL;
        return -1;
    }
    len = strlen(path);
    if (len >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(tmp, path, len + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) < 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int parent_dir(const char *path, char *out, size_t n) {
    const char *slash;
    size_t len;
    slash = strrchr(path, '/');
    if (!slash || slash == path) {
        snprintf(out, n, "/");
        return 0;
    }
    len = (size_t)(slash - path);
    if (len >= n) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, path, len);
    out[len] = '\0';
    return 0;
}

static int join_root(char *out, size_t n, const char *newroot, const char *abs) {
    int r;
    if (!abs || abs[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    r = snprintf(out, n, "%s%s", newroot, abs);
    if (r < 0 || (size_t)r >= n) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int real_abs(const char *in, char *out, size_t n) {
    char *r;
    if (!in || !in[0]) {
        errno = EINVAL;
        return -1;
    }
    r = realpath(in, NULL);
    if (!r) {
        /* Path may not exist yet (unix socket). Keep absolute form. */
        if (in[0] == '/') {
            if (strlen(in) >= n) {
                errno = ENAMETOOLONG;
                return -1;
            }
            memcpy(out, in, strlen(in) + 1);
            return 0;
        }
        return -1;
    }
    if (strlen(r) >= n) {
        free(r);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, r, strlen(r) + 1);
    free(r);
    return 0;
}

static int map_ids(pid_t pid, uid_t uid, gid_t gid) {
    char path[64], buf[64];
    snprintf(path, sizeof(path), "/proc/%d/setgroups", (int)pid);
    if (write_file(path, "deny\n") < 0)
        return -1;
    snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)pid);
    snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned)uid);
    if (write_file(path, buf) < 0)
        return -1;
    snprintf(path, sizeof(path), "/proc/%d/gid_map", (int)pid);
    snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned)gid);
    if (write_file(path, buf) < 0)
        return -1;
    return 0;
}

static int bind_one(const char *src, const char *dst, int rdonly) {
    struct stat st;
    char parent[PATH_MAX];
    int flags;

    if (lstat(src, &st) < 0)
        return 0;

    if (parent_dir(dst, parent, sizeof(parent)) < 0)
        return -1;
    if (strcmp(parent, "/") != 0 && mkdir_p(parent, 0755) < 0)
        return -1;

    if (S_ISLNK(st.st_mode)) {
        char target[PATH_MAX];
        ssize_t n = readlink(src, target, sizeof(target) - 1);
        if (n < 0)
            return -1;
        target[n] = '\0';
        if (symlink(target, dst) < 0 && errno != EEXIST)
            return -1;
        return 0;
    }

    if (S_ISDIR(st.st_mode)) {
        if (mkdir(dst, 0755) < 0 && errno != EEXIST)
            return -1;
    } else {
        int fd = open(dst, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
        if (fd < 0 && errno != EEXIST)
            return -1;
        if (fd >= 0)
            close(fd);
    }

    if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) < 0)
        return -1;
    flags = MS_BIND | MS_REC | MS_REMOUNT | MS_NOSUID | MS_NODEV;
    if (rdonly)
        flags |= MS_RDONLY;
    if (mount(NULL, dst, NULL, flags, NULL) < 0)
        return -1;
    return 0;
}

static int bind_into(const char *newroot, const char *abs, int rdonly) {
    char dst[PATH_MAX];
    if (join_root(dst, sizeof(dst), newroot, abs) < 0)
        return -1;
    return bind_one(abs, dst, rdonly);
}

static int make_dev_links(const char *newroot) {
    char dst[PATH_MAX];
    if (join_root(dst, sizeof(dst), newroot, "/dev/fd") < 0)
        return -1;
    unlink(dst);
    if (symlink("/proc/self/fd", dst) < 0 && errno != EEXIST)
        return -1;
    if (join_root(dst, sizeof(dst), newroot, "/dev/stdin") < 0)
        return -1;
    unlink(dst);
    if (symlink("/proc/self/fd/0", dst) < 0 && errno != EEXIST)
        return -1;
    if (join_root(dst, sizeof(dst), newroot, "/dev/stdout") < 0)
        return -1;
    unlink(dst);
    if (symlink("/proc/self/fd/1", dst) < 0 && errno != EEXIST)
        return -1;
    if (join_root(dst, sizeof(dst), newroot, "/dev/stderr") < 0)
        return -1;
    unlink(dst);
    if (symlink("/proc/self/fd/2", dst) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int bring_up_lo(void) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "lo");
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        close(fd);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int drop_caps(void) {
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];

    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall(SYS_capset, &hdr, data) < 0)
        return -1;
#ifdef PR_CAP_AMBIENT
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
#endif
    for (int i = 0; i <= 40; i++)
        prctl(PR_CAPBSET_DROP, i, 0, 0, 0);
    return 0;
}

static uint64_t landlock_fs_handled(int abi) {
    uint64_t fs = HF_FS_ABI1;
    if (abi >= 2)
        fs |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3)
        fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5)
        fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    return fs;
}

static uint64_t landlock_ro(uint64_t handled) {
    return handled & (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                      LANDLOCK_ACCESS_FS_READ_DIR);
}

static uint64_t landlock_rw(uint64_t handled) {
    return handled &
           (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
            LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
            LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV);
}

static uint64_t landlock_dev(uint64_t handled) {
    return handled & (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                      LANDLOCK_ACCESS_FS_IOCTL_DEV);
}

static int landlock_add(int ruleset, const char *path, uint64_t access) {
    int fd;
    int is_dir = 0;
    struct landlock_path_beneath_attr attr;

    if (!path || !path[0] || access == 0)
        return 0;
    fd = open(path, O_PATH | O_CLOEXEC | O_DIRECTORY);
    if (fd >= 0) {
        is_dir = 1;
    } else {
        fd = open(path, O_PATH | O_CLOEXEC);
        if (fd < 0)
            return 0;
    }
    if (!is_dir) {
        access &= (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                   LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
                   LANDLOCK_ACCESS_FS_IOCTL_DEV);
    }
    memset(&attr, 0, sizeof(attr));
    attr.allowed_access = access;
    attr.parent_fd = fd;
    if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &attr, 0) <
        0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    close(fd);
    return 0;
}

static int apply_landlock(const hf_cfg *cfg) {
    int abi;
    int ruleset;
    uint64_t handled;
    uint64_t ro, rw, dev;
    struct landlock_ruleset_attr attr;

    abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
                       LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        warnx("Landlock is required (Linux 5.13+); this kernel does not expose it");
        return -1;
    }
    handled = landlock_fs_handled(abi);
    memset(&attr, 0, sizeof(attr));
    attr.handled_access_fs = handled;
    ruleset = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (ruleset < 0)
        return -1;

    ro = landlock_ro(handled);
    rw = landlock_rw(handled);
    dev = landlock_dev(handled);

    if (landlock_add(ruleset, "/usr", ro) < 0)
        goto fail;
    if (landlock_add(ruleset, "/etc", ro) < 0)
        goto fail;
    if (landlock_add(ruleset, "/proc", ro) < 0)
        goto fail;
    if (landlock_add(ruleset, "/dev", dev | (handled & LANDLOCK_ACCESS_FS_READ_DIR)) < 0)
        goto fail;
    if (landlock_add(ruleset, "/tmp", rw) < 0)
        goto fail;
    if (landlock_add(ruleset, cfg->root, rw) < 0)
        goto fail;
    if (landlock_add(ruleset, cfg->cwd, rw) < 0)
        goto fail;
    for (int i = 0; i < cfg->n_ro; i++) {
        if (landlock_add(ruleset, cfg->ro[i], ro) < 0)
            goto fail;
    }
    for (int i = 0; i < cfg->n_rw; i++) {
        if (landlock_add(ruleset, cfg->rw[i], rw) < 0)
            goto fail;
    }
    if (cfg->sock[0] && landlock_add(ruleset, cfg->sock, dev | LANDLOCK_ACCESS_FS_WRITE_FILE |
                                                             LANDLOCK_ACCESS_FS_READ_FILE) <
                            0)
        goto fail;
    if (cfg->use_preload && cfg->preload[0] &&
        landlock_add(ruleset, cfg->preload, ro) < 0)
        goto fail;

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        goto fail;
    if (syscall(SYS_landlock_restrict_self, ruleset, 0) < 0)
        goto fail;
    close(ruleset);
    return 0;
fail:
    close(ruleset);
    return -1;
}

static int bpf_push(struct sock_filter *f, int *n, int cap, uint16_t code, uint8_t jt,
                    uint8_t jf, uint32_t k) {
    if (*n >= cap) {
        errno = ENOMEM;
        return -1;
    }
    f[*n].code = code;
    f[*n].jt = jt;
    f[*n].jf = jf;
    f[*n].k = k;
    (*n)++;
    return 0;
}

static int bpf_stmt(struct sock_filter *f, int *n, int cap, uint16_t code, uint32_t k) {
    return bpf_push(f, n, cap, code, 0, 0, k);
}

static int bpf_jump(struct sock_filter *f, int *n, int cap, uint16_t code, uint32_t k,
                    uint8_t jt, uint8_t jf) {
    return bpf_push(f, n, cap, code, jt, jf, k);
}

static int apply_seccomp(void) {
    struct sock_filter filter[HF_MAX_FILTER];
    struct sock_fprog prog;
    int n = 0;
    int i;
    static const int k_kill[] = {
#ifdef __NR_ptrace
        __NR_ptrace,
#endif
#ifdef __NR_process_vm_readv
        __NR_process_vm_readv,
#endif
#ifdef __NR_process_vm_writev
        __NR_process_vm_writev,
#endif
#ifdef __NR_bpf
        __NR_bpf,
#endif
#ifdef __NR_userfaultfd
        __NR_userfaultfd,
#endif
#ifdef __NR_perf_event_open
        __NR_perf_event_open,
#endif
#ifdef __NR_kexec_load
        __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
        __NR_kexec_file_load,
#endif
#ifdef __NR_init_module
        __NR_init_module,
#endif
#ifdef __NR_finit_module
        __NR_finit_module,
#endif
#ifdef __NR_delete_module
        __NR_delete_module,
#endif
#ifdef __NR_open_by_handle_at
        __NR_open_by_handle_at,
#endif
#ifdef __NR_io_uring_setup
        __NR_io_uring_setup,
#endif
#ifdef __NR_io_uring_enter
        __NR_io_uring_enter,
#endif
#ifdef __NR_io_uring_register
        __NR_io_uring_register,
#endif
    };
    static const int k_eperm[] = {
#ifdef __NR_mount
        __NR_mount,
#endif
#ifdef __NR_umount2
        __NR_umount2,
#endif
#ifdef __NR_pivot_root
        __NR_pivot_root,
#endif
#ifdef __NR_chroot
        __NR_chroot,
#endif
#ifdef __NR_unshare
        __NR_unshare,
#endif
#ifdef __NR_setns
        __NR_setns,
#endif
#ifdef __NR_reboot
        __NR_reboot,
#endif
#ifdef __NR_swapon
        __NR_swapon,
#endif
#ifdef __NR_swapoff
        __NR_swapoff,
#endif
#ifdef __NR_sethostname
        __NR_sethostname,
#endif
#ifdef __NR_setdomainname
        __NR_setdomainname,
#endif
#ifdef __NR_acct
        __NR_acct,
#endif
#ifdef __NR_settimeofday
        __NR_settimeofday,
#endif
#ifdef __NR_clock_settime
        __NR_clock_settime,
#endif
#ifdef __NR_clock_adjtime
        __NR_clock_adjtime,
#endif
#ifdef __NR_adjtimex
        __NR_adjtimex,
#endif
#ifdef __NR_ioperm
        __NR_ioperm,
#endif
#ifdef __NR_iopl
        __NR_iopl,
#endif
#ifdef __NR_syslog
        __NR_syslog,
#endif
#ifdef __NR_fanotify_init
        __NR_fanotify_init,
#endif
#ifdef __NR_name_to_handle_at
        __NR_name_to_handle_at,
#endif
#ifdef __NR_add_key
        __NR_add_key,
#endif
#ifdef __NR_request_key
        __NR_request_key,
#endif
#ifdef __NR_keyctl
        __NR_keyctl,
#endif
#ifdef __NR_fsopen
        __NR_fsopen,
#endif
#ifdef __NR_fsconfig
        __NR_fsconfig,
#endif
#ifdef __NR_fsmount
        __NR_fsmount,
#endif
#ifdef __NR_move_mount
        __NR_move_mount,
#endif
#ifdef __NR_open_tree
        __NR_open_tree,
#endif
#ifdef __NR_mount_setattr
        __NR_mount_setattr,
#endif
#ifdef __NR_pidfd_getfd
        __NR_pidfd_getfd,
#endif
#ifdef __NR_capset
        __NR_capset,
#endif
#ifdef __NR_setuid
        __NR_setuid,
#endif
#ifdef __NR_setgid
        __NR_setgid,
#endif
#ifdef __NR_setreuid
        __NR_setreuid,
#endif
#ifdef __NR_setregid
        __NR_setregid,
#endif
#ifdef __NR_setresuid
        __NR_setresuid,
#endif
#ifdef __NR_setresgid
        __NR_setresgid,
#endif
#ifdef __NR_seccomp
        __NR_seccomp,
#endif
    };
    uint32_t ns_bits = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER |
                       CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWTIME;

    /* Verify x86_64. Unknown arch is kill. */
    if (bpf_stmt(filter, &n, HF_MAX_FILTER, BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)))
        return -1;
    if (bpf_jump(filter, &n, HF_MAX_FILTER, BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1,
                 0))
        return -1;
    if (bpf_stmt(filter, &n, HF_MAX_FILTER, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))
        return -1;

    if (bpf_stmt(filter, &n, HF_MAX_FILTER, BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)))
        return -1;

#ifdef __NR_clone3
    /* glibc/python fall back to clone() if clone3 returns ENOSYS. */
    if (bpf_jump(filter, &n, HF_MAX_FILTER, BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1))
        return -1;
    if (bpf_stmt(filter, &n, HF_MAX_FILTER, BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS))
        return -1;
#endif

#ifdef __NR_clone
    /* clone: allow, but kill if namespace flags are set.
     * If nr is not clone, skip the next 4 instructions. A still holds nr.
     */
    if (bpf_jump(filter, &n, HF_MAX_FILTER, BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4))
        return -1;
    if (bpf_stmt(filter, &n, HF_MAX_FILTER, BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, args[0])))
        return -1;
    if (bpf_jump(filter, &n, HF_MAX_FILTER, BPF_JMP | BPF_JSET | BPF_K, ns_bits, 0, 1))
        return -1;
    if (bpf_stmt(filter, &n, HF_MAX_FILTER, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))
        return -1;
    if (bpf_stmt(filter, &n, HF_MAX_FILTER, BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
        return -1;
#endif

    for (i = 0; i < (int)(sizeof(k_kill) / sizeof(k_kill[0])); i++) {
        if (bpf_jump(filter, &n, HF_MAX_FILTER, BPF_JMP | BPF_JEQ | BPF_K,
                     (uint32_t)k_kill[i], 0, 1))
            return -1;
        if (bpf_stmt(filter, &n, HF_MAX_FILTER, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))
            return -1;
    }
    for (i = 0; i < (int)(sizeof(k_eperm) / sizeof(k_eperm[0])); i++) {
        if (bpf_jump(filter, &n, HF_MAX_FILTER, BPF_JMP | BPF_JEQ | BPF_K,
                     (uint32_t)k_eperm[i], 0, 1))
            return -1;
        if (bpf_stmt(filter, &n, HF_MAX_FILTER, BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM))
            return -1;
    }
    if (bpf_stmt(filter, &n, HF_MAX_FILTER, BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
        return -1;

    prog.len = (unsigned short)n;
    prog.filter = filter;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
        return -1;
    return 0;
}

static int setup_mounts(const hf_cfg *cfg) {
    char newroot[PATH_MAX];
    char old[PATH_MAX];
    char dst[PATH_MAX];
    int i;

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        return -1;

    snprintf(newroot, sizeof(newroot), "%s", cfg->newroot);
    if (newroot[0] == '\0')
        return -1;
    if (mkdir(newroot, 0755) < 0 && errno != EEXIST)
        return -1;
    if (mount("holdfast-root", newroot, "tmpfs", MS_NOSUID | MS_NODEV, "mode=755,size=64m") <
        0)
        return -1;

    if (join_root(dst, sizeof(dst), newroot, "/usr") < 0)
        return -1;
    if (mkdir_p(dst, 0755) < 0)
        return -1;
    if (bind_one("/usr", dst, 1) < 0)
        return -1;

    for (i = 0; hf_usr_symlinks[i]; i++) {
        if (bind_into(newroot, hf_usr_symlinks[i], 1) < 0)
            return -1;
    }

    if (join_root(dst, sizeof(dst), newroot, "/etc") < 0)
        return -1;
    if (mkdir_p(dst, 0755) < 0)
        return -1;
    for (i = 0; hf_ro_etc[i]; i++) {
        if (bind_into(newroot, hf_ro_etc[i], 1) < 0)
            return -1;
    }

    if (join_root(dst, sizeof(dst), newroot, "/dev") < 0)
        return -1;
    if (mkdir_p(dst, 0755) < 0)
        return -1;
    for (i = 0; hf_dev_nodes[i]; i++) {
        if (bind_into(newroot, hf_dev_nodes[i], 0) < 0)
            return -1;
    }
    if (make_dev_links(newroot) < 0)
        return -1;

    if (join_root(dst, sizeof(dst), newroot, "/proc") < 0)
        return -1;
    if (mkdir_p(dst, 0755) < 0)
        return -1;
    if (mount("proc", dst, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, "hidepid=2") < 0) {
        if (mount("proc", dst, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) < 0)
            return -1;
    }

    if (join_root(dst, sizeof(dst), newroot, "/tmp") < 0)
        return -1;
    if (mkdir_p(dst, 0755) < 0)
        return -1;
    if (mount("tmp", dst, "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777,size=64m") < 0)
        return -1;

    if (bind_into(newroot, cfg->root, 0) < 0)
        return -1;
    if (strcmp(cfg->cwd, cfg->root) != 0 && bind_into(newroot, cfg->cwd, 0) < 0)
        return -1;
    for (i = 0; i < cfg->n_ro; i++) {
        if (bind_into(newroot, cfg->ro[i], 1) < 0)
            return -1;
    }
    for (i = 0; i < cfg->n_rw; i++) {
        if (bind_into(newroot, cfg->rw[i], 0) < 0)
            return -1;
    }
    if (cfg->use_preload && cfg->preload[0] &&
        strncmp(cfg->preload, "/usr/", 5) != 0 &&
        strncmp(cfg->preload, cfg->root, strlen(cfg->root)) != 0) {
        if (bind_into(newroot, cfg->preload, 1) < 0)
            return -1;
    }

    if (cfg->sock[0]) {
        struct stat st;
        if (stat(cfg->sock, &st) == 0) {
            if (bind_into(newroot, cfg->sock, 0) < 0)
                return -1;
        }
    }

    if (join_root(old, sizeof(old), newroot, "/.oldroot") < 0)
        return -1;
    if (mkdir(old, 0755) < 0 && errno != EEXIST)
        return -1;
    if (chdir(newroot) < 0)
        return -1;
    if (syscall(SYS_pivot_root, ".", ".oldroot") < 0)
        return -1;
    if (chdir("/") < 0)
        return -1;
    if (umount2("/.oldroot", MNT_DETACH) < 0)
        return -1;
    rmdir("/.oldroot");
    return 0;
}

static void apply_env(const hf_cfg *cfg) {
    setenv("HOLDFAST_JAIL", "1", 1);
    setenv("HOLDFAST_SOCK", cfg->sock[0] ? cfg->sock : HF_DEFAULT_SOCK, 1);
    if (cfg->session[0])
        setenv("HOLDFAST_SESSION", cfg->session, 1);
    if (cfg->member >= 0) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%d", cfg->member);
        setenv("HOLDFAST_JAIL_MEMBER", buf, 1);
    }
    setenv("HOME", "/tmp", 1);
    setenv("TMPDIR", "/tmp", 1);
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 0);
    setenv("PYTHONDONTWRITEBYTECODE", "1", 0);
    setenv("PYTHONUNBUFFERED", "1", 0);
    setenv("LD_BIND_NOW", "1", 0);
    if (cfg->use_preload && cfg->preload[0]) {
        const char *old = getenv("LD_PRELOAD");
        char buf[PATH_MAX * 2];
        if (old && old[0])
            snprintf(buf, sizeof(buf), "%s:%s", cfg->preload, old);
        else
            snprintf(buf, sizeof(buf), "%s", cfg->preload);
        setenv("LD_PRELOAD", buf, 1);
    } else {
        unsetenv("LD_PRELOAD");
    }
}

static int jailed_exec(const hf_cfg *cfg) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
        die(1, "PR_SET_PDEATHSIG");
    prctl(PR_SET_NAME, "holdfast-jail");
    if (sethostname(cfg->hostname, strlen(cfg->hostname)) < 0)
        die(1, "sethostname");
    if (cfg->net_none && bring_up_lo() < 0)
        warnx("could not bring up loopback");
    if (setup_mounts(cfg) < 0)
        die(1, "mount jail");
    if (chdir(cfg->cwd) < 0 && chdir(cfg->root) < 0 && chdir("/") < 0)
        die(1, "chdir workspace");
    if (apply_landlock(cfg) < 0)
        die(1, "landlock");
    if (drop_caps() < 0)
        die(1, "drop capabilities");
    if (apply_seccomp() < 0)
        die(1, "seccomp");
    apply_env(cfg);
    execvp(cfg->argv[0], cfg->argv);
    die(127, "exec %s", cfg->argv[0]);
    return -1;
}

static void usage(FILE *fp) {
    fputs(
        "Usage: holdfast-jail [options] -- <command>...\n"
        "\n"
        "Kernel jail for Holdfast agent swarms. Namespaces + Landlock +\n"
        "seccomp. Default is fail-closed: missing Landlock or seccomp refuses exec.\n"
        "\n"
        "  --root DIR        workspace bind (default: cwd), read-write\n"
        "  --sock PATH       Holdfast daemon socket (default: $HOLDFAST_SOCK)\n"
        "  --preload PATH    libholdfast.so (human gate; optional)\n"
        "  --session ID      HOLDFAST_SESSION\n"
        "  --net host|none   host (default) keeps host net; none is a net ns\n"
        "  --hostname NAME   UTS hostname (default: holdfast or holdfast-N)\n"
        "  --member N        swarm member index\n"
        "  --ro PATH         extra read-only bind (repeatable)\n"
        "  --rw PATH         extra read-write bind (repeatable)\n"
        "  --no-preload      kernel jail only; skip LD_PRELOAD\n"
        "  --version         print " HF_JAIL_VERSION "\n"
        "  --help            this text\n",
        fp);
}

static int add_bind(char binds[HF_MAX_BINDS][PATH_MAX], int *n, const char *path) {
    if (*n >= HF_MAX_BINDS) {
        fprintf(stderr, "holdfast-jail: too many binds\n");
        return -1;
    }
    if (real_abs(path, binds[*n], PATH_MAX) < 0) {
        fprintf(stderr, "holdfast-jail: bad bind path %s: %s\n", path, strerror(errno));
        return -1;
    }
    (*n)++;
    return 0;
}

static int parse_args(int argc, char **argv, hf_cfg *cfg) {
    static const struct option opts[] = {
        {"root", required_argument, NULL, 'r'},
        {"sock", required_argument, NULL, 's'},
        {"preload", required_argument, NULL, 'p'},
        {"session", required_argument, NULL, 'S'},
        {"net", required_argument, NULL, 'n'},
        {"hostname", required_argument, NULL, 'H'},
        {"member", required_argument, NULL, 'm'},
        {"ro", required_argument, NULL, 'o'},
        {"rw", required_argument, NULL, 'w'},
        {"no-preload", no_argument, NULL, 'N'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {0, 0, 0, 0},
    };
    int c;
    const char *env_sock;
    const char *env_session;
    char *cwd;

    memset(cfg, 0, sizeof(*cfg));
    cfg->member = -1;
    cfg->use_preload = 1;

    env_sock = getenv("HOLDFAST_SOCK");
    snprintf(cfg->sock, sizeof(cfg->sock), "%s",
             env_sock && env_sock[0] ? env_sock : HF_DEFAULT_SOCK);
    env_session = getenv("HOLDFAST_SESSION");
    if (env_session)
        snprintf(cfg->session, sizeof(cfg->session), "%s", env_session);

    cwd = getcwd(cfg->cwd, sizeof(cfg->cwd));
    if (!cwd) {
        fprintf(stderr, "holdfast-jail: getcwd: %s\n", strerror(errno));
        return 2;
    }
    snprintf(cfg->root, sizeof(cfg->root), "%s", cfg->cwd);

    opterr = 0;
    while ((c = getopt_long(argc, argv, "+", opts, NULL)) != -1) {
        switch (c) {
        case 'r':
            if (real_abs(optarg, cfg->root, sizeof(cfg->root)) < 0) {
                fprintf(stderr, "holdfast-jail: --root %s: %s\n", optarg,
                        strerror(errno));
                return 2;
            }
            break;
        case 's':
            snprintf(cfg->sock, sizeof(cfg->sock), "%s", optarg);
            break;
        case 'p':
            snprintf(cfg->preload, sizeof(cfg->preload), "%s", optarg);
            break;
        case 'S':
            snprintf(cfg->session, sizeof(cfg->session), "%s", optarg);
            break;
        case 'n':
            if (strcmp(optarg, "none") == 0 || strcmp(optarg, "private") == 0)
                cfg->net_none = 1;
            else if (strcmp(optarg, "host") == 0)
                cfg->net_none = 0;
            else {
                fprintf(stderr, "holdfast-jail: --net expects host or none\n");
                return 2;
            }
            break;
        case 'H':
            snprintf(cfg->hostname, sizeof(cfg->hostname), "%s", optarg);
            break;
        case 'm':
            cfg->member = atoi(optarg);
            break;
        case 'o':
            if (add_bind(cfg->ro, &cfg->n_ro, optarg) < 0)
                return 2;
            break;
        case 'w':
            if (add_bind(cfg->rw, &cfg->n_rw, optarg) < 0)
                return 2;
            break;
        case 'N':
            cfg->use_preload = 0;
            break;
        case 'h':
            usage(stdout);
            exit(0);
        case 'V':
            puts(HF_JAIL_VERSION);
            exit(0);
        default:
            usage(stderr);
            return 2;
        }
    }
    if (optind >= argc) {
        usage(stderr);
        return 2;
    }
    if (strcmp(argv[optind], "--") == 0)
        optind++;
    if (optind >= argc) {
        usage(stderr);
        return 2;
    }
    cfg->argv = argv + optind;

    if (!cfg->hostname[0]) {
        if (cfg->member >= 0)
            snprintf(cfg->hostname, sizeof(cfg->hostname), "holdfast-%d", cfg->member);
        else
            snprintf(cfg->hostname, sizeof(cfg->hostname), "holdfast");
    }
    {
        char sock_abs[PATH_MAX];
        if (real_abs(cfg->sock, sock_abs, sizeof(sock_abs)) == 0)
            snprintf(cfg->sock, sizeof(cfg->sock), "%s", sock_abs);
    }
    if (cfg->use_preload && !cfg->preload[0]) {
        const char *candidates[] = {
            "/workspace/preload/libholdfast.so",
            "preload/libholdfast.so",
            "/usr/local/lib/libholdfast.so",
            NULL,
        };
        for (int i = 0; candidates[i]; i++) {
            char abs[PATH_MAX];
            if (real_abs(candidates[i], abs, sizeof(abs)) == 0 && access(abs, R_OK) == 0) {
                snprintf(cfg->preload, sizeof(cfg->preload), "%s", abs);
                break;
            }
        }
        if (!cfg->preload[0])
            cfg->use_preload = 0;
    } else if (cfg->use_preload && cfg->preload[0]) {
        char abs[PATH_MAX];
        if (real_abs(cfg->preload, abs, sizeof(abs)) == 0)
            snprintf(cfg->preload, sizeof(cfg->preload), "%s", abs);
        if (access(cfg->preload, R_OK) != 0) {
            fprintf(stderr, "holdfast-jail: preload not readable at %s\n", cfg->preload);
            return 2;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    hf_cfg cfg;
    int to_parent[2], to_child[2];
    pid_t child;
    uid_t uid = getuid();
    gid_t gid = getgid();
    char c = 0;
    int st;
    int rc;

    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        puts(HF_JAIL_VERSION);
        return 0;
    }

    rc = parse_args(argc, argv, &cfg);
    if (rc != 0)
        return rc;

    {
        char tmpl[] = "/tmp/holdfast-jail-XXXXXX";
        char *dir = mkdtemp(tmpl);
        if (!dir) {
            perror("holdfast-jail: mkdtemp");
            return 1;
        }
        snprintf(cfg.newroot, sizeof(cfg.newroot), "%s", dir);
    }

    if (pipe(to_parent) < 0 || pipe(to_child) < 0) {
        perror("holdfast-jail: pipe");
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("holdfast-jail: fork");
        return 1;
    }
    if (child == 0) {
        int unshare_flags;
        pid_t inner;

        close(to_parent[0]);
        close(to_child[1]);
        if (unshare(CLONE_NEWUSER) < 0)
            die(2, "unshare user namespace");
        if (write(to_parent[1], "u", 1) != 1)
            die(3, "sync unshare");
        if (read(to_child[0], &c, 1) != 1)
            die(4, "wait for uid_map");

        unshare_flags = HF_NS_FLAGS;
        if (cfg.net_none)
            unshare_flags |= CLONE_NEWNET;
        if (unshare(unshare_flags) < 0) {
            unshare_flags &= ~CLONE_NEWCGROUP;
            if (unshare(unshare_flags) < 0)
                die(5, "unshare jail namespaces");
        }

        inner = fork();
        if (inner < 0)
            die(6, "fork pid namespace");
        if (inner > 0) {
            int inner_st;
            close(to_parent[1]);
            close(to_child[0]);
            while (waitpid(inner, &inner_st, 0) < 0) {
                if (errno == EINTR)
                    continue;
                _exit(1);
            }
            if (WIFEXITED(inner_st))
                _exit(WEXITSTATUS(inner_st));
            if (WIFSIGNALED(inner_st))
                _exit(128 + WTERMSIG(inner_st));
            _exit(1);
        }
        close(to_parent[1]);
        close(to_child[0]);
        errno = 0;
        if (jailed_exec(&cfg) < 0)
            die(127, "exec %s", cfg.argv[0]);
        _exit(127);
    }

    close(to_parent[1]);
    close(to_child[0]);
    if (read(to_parent[0], &c, 1) != 1) {
        perror("holdfast-jail: wait for child unshare");
        return 1;
    }
    if (map_ids(child, uid, gid) < 0) {
        perror("holdfast-jail: uid/gid map");
        return 1;
    }
    if (write(to_child[1], "x", 1) != 1) {
        perror("holdfast-jail: signal mapped");
        return 1;
    }
    close(to_parent[0]);
    close(to_child[1]);
    while (waitpid(child, &st, 0) < 0) {
        if (errno == EINTR)
            continue;
        perror("holdfast-jail: waitpid");
        return 1;
    }
    rmdir(cfg.newroot);
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return 1;
}
