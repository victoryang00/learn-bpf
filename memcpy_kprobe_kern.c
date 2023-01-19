#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("kprobe/__x64_sys_munmap")
int bpf_prog1(struct pt_regs *ctx)
{
    long size;
    long address;
    char fmt[] = "munmap %ld %ld %llu\n";
    u32 pid = bpf_get_current_pid_tgid();

    bpf_probe_read(&size, sizeof(size), (void *)&PT_REGS_PARM2(ctx));
    bpf_probe_read(&address, sizeof(address), (void *)&PT_REGS_PARM1(ctx));

    bpf_trace_printk(fmt, sizeof(fmt), size, address, bpf_ktime_get_ns());

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
