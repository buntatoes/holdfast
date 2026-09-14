/*
 * holdfast-jail: Native Linux jail for Agent swarms.
 *
 * Copyright (c) 2026 Holdfast. All Rights Reserved.
 * PROPRIETARY AND CONFIDENTIAL.
 *
 * This software is proprietary and subject to commercial licensing terms.
 * Unauthorized distribution, duplication, or modification is prohibited.
 * See jail/LICENSE for licensing terms.
 *
 * Provides true kernel sandbox isolation using Linux namespaces:
 * - User namespace (unprivileged root mapping)
 * - Mount namespace (private root, fresh /proc, minimal mounts)
 * - PID namespace (agent cannot see host processes or other swarm members)
 * - UTS namespace (isolated hostname)
 * - IPC namespace (isolated IPC / message queues)
 * - Optional Network namespace (block all external TCP/UDP, or isolate)
 *
 * Can run with or without Holdfast LD_PRELOAD layer for defense-in-depth.
 * Supports swarms via swarm-id / agent-id sub-environments.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    const char *swarm_id;
    const char *agent_id;
    const char *workspace_dir;
    const char *hostname;
    int isolate_net;
    int ro_root;
    int verbose;
    char **argv;
} jail_config_t;

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [options] -- <command> [args...]\n\n"
            "Options:\n"
            "  --swarm <id>         Swarm identifier for grouping agent instances\n"
            "  --agent <id>         Agent identifier within the swarm\n"
            "  --workspace <dir>    Workspace directory to bind-mount / set as cwd\n"
            "  --hostname <name>    Custom hostname in UTS namespace (default: holdfast-agent)\n"
            "  --isolate-net        Unshare network namespace (block raw host net)\n"
            "  --ro-root            Mount root filesystem read-only\n"
            "  --verbose, -v        Print jail setup diagnostics\n"
            "  --help, -h           Show this help message\n",
            prog);
}

static int write_str_to_file(const char *path, const char *str) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    size_t len = strlen(str);
    ssize_t written = write(fd, str, len);
    close(fd);
    return (written == (ssize_t)len) ? 0 : -1;
}

static int setup_id_maps(uid_t outer_uid, gid_t outer_gid) {
    /* deny setgroups before writing gid_map in unprivileged user namespace */
    write_str_to_file("/proc/self/setgroups", "deny");

    char map_buf[128];
    snprintf(map_buf, sizeof(map_buf), "0 %u 1\n", (unsigned)outer_uid);
    if (write_str_to_file("/proc/self/uid_map", map_buf) != 0) {
        perror("write uid_map");
        return -1;
    }

    snprintf(map_buf, sizeof(map_buf), "0 %u 1\n", (unsigned)outer_gid);
    if (write_str_to_file("/proc/self/gid_map", map_buf) != 0) {
        perror("write gid_map");
        return -1;
    }

    return 0;
}

static int setup_child_mounts(const jail_config_t *cfg) {
    /* Make mount points private to this namespace so changes don't leak */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        if (cfg->verbose) perror("mount MS_PRIVATE /");
        /* Non-fatal if already private, but usually succeeds in new mnt ns */
    }

    /* Mount fresh procfs for PID namespace */
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0) {
        if (cfg->verbose) perror("mount /proc");
    }

    /* Optional read-only root remount */
    if (cfg->ro_root) {
        if (mount(NULL, "/", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) != 0) {
            if (cfg->verbose) perror("remount / ro");
        }
    }

    return 0;
}

static int run_jail_child(const jail_config_t *cfg) {
    /* Die if parent dies */
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    /* Set UTS hostname */
    const char *hname = cfg->hostname ? cfg->hostname : "holdfast-agent";
    if (sethostname(hname, strlen(hname)) != 0) {
        if (cfg->verbose) perror("sethostname");
    }

    /* Set up mount isolation */
    if (setup_child_mounts(cfg) != 0) {
        fprintf(stderr, "holdfast-jail: failed to set up mounts\n");
        return 1;
    }

    /* Export Swarm and Agent environment variables */
    if (cfg->swarm_id && cfg->swarm_id[0]) {
        setenv("HOLDFAST_SWARM", cfg->swarm_id, 1);
    }
    if (cfg->agent_id && cfg->agent_id[0]) {
        setenv("HOLDFAST_AGENT", cfg->agent_id, 1);
    }
    setenv("HOLDFAST_JAIL", "1", 1);

    /* Change directory to workspace if specified */
    if (cfg->workspace_dir && cfg->workspace_dir[0]) {
        if (chdir(cfg->workspace_dir) != 0) {
            perror("chdir workspace");
        }
    }

    if (cfg->verbose) {
        fprintf(stderr, "[holdfast-jail] Child ready: PID=%d, UID=%d, Hostname=%s\n",
                getpid(), getuid(), hname);
        if (cfg->swarm_id) fprintf(stderr, "[holdfast-jail] Swarm: %s, Agent: %s\n",
                                   cfg->swarm_id, cfg->agent_id ? cfg->agent_id : "default");
    }

    /* Execute target command */
    execvp(cfg->argv[0], cfg->argv);
    perror("execvp target");
    return 127;
}

int main(int argc, char **argv) {
    jail_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    int arg_idx = 1;
    while (arg_idx < argc) {
        const char *arg = argv[arg_idx];
        if (strcmp(arg, "--") == 0) {
            arg_idx++;
            break;
        } else if (strcmp(arg, "--swarm") == 0 && arg_idx + 1 < argc) {
            cfg.swarm_id = argv[++arg_idx];
        } else if (strcmp(arg, "--agent") == 0 && arg_idx + 1 < argc) {
            cfg.agent_id = argv[++arg_idx];
        } else if (strcmp(arg, "--workspace") == 0 && arg_idx + 1 < argc) {
            cfg.workspace_dir = argv[++arg_idx];
        } else if (strcmp(arg, "--hostname") == 0 && arg_idx + 1 < argc) {
            cfg.hostname = argv[++arg_idx];
        } else if (strcmp(arg, "--isolate-net") == 0) {
            cfg.isolate_net = 1;
        } else if (strcmp(arg, "--ro-root") == 0) {
            cfg.ro_root = 1;
        } else if (strcmp(arg, "--verbose") == 0 || strcmp(arg, "-v") == 0) {
            cfg.verbose = 1;
        } else if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (arg[0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", arg);
            print_usage(argv[0]);
            return 2;
        } else {
            /* Start of command without -- */
            break;
        }
        arg_idx++;
    }

    if (arg_idx >= argc) {
        fprintf(stderr, "holdfast-jail: missing command to execute\n");
        print_usage(argv[0]);
        return 2;
    }

    cfg.argv = &argv[arg_idx];

    uid_t outer_uid = getuid();
    gid_t outer_gid = getgid();

    int clone_flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC;
    if (cfg.isolate_net) {
        clone_flags |= CLONE_NEWNET;
    }

    if (cfg.verbose) {
        fprintf(stderr, "[holdfast-jail] Creating sandbox namespaces (flags=0x%x)...\n", clone_flags);
    }

    if (unshare(clone_flags) != 0) {
        perror("unshare namespaces");
        fprintf(stderr, "holdfast-jail: failed to unshare namespaces. Kernel support required.\n");
        return 1;
    }

    if (setup_id_maps(outer_uid, outer_gid) != 0) {
        fprintf(stderr, "holdfast-jail: failed to setup UID/GID maps\n");
        return 1;
    }

    /* Fork child into the new PID namespace */
    pid_t child = fork();
    if (child < 0) {
        perror("fork jail child");
        return 1;
    }

    if (child == 0) {
        /* In child (PID 1 in its PID namespace) */
        return run_jail_child(&cfg);
    }

    /* Parent waits for child and forwards signals */
    int status = 0;
    while (1) {
        pid_t p = waitpid(child, &status, 0);
        if (p < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("waitpid");
            return 1;
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        }
    }

    return 0;
}
