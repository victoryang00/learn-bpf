#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"


struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(size_t),
	.value_size = sizeof(u64),
	.max_entries = 32,
};

SEC("kprobe/__x64_sys_mmap")
int bpf_prog1(struct pt_regs *ctx)
{
	size_t size;
	u32 *val, count_start = 0;

	bpf_probe_read(&size, sizeof(size), (void *)&PT_REGS_PARM2(ctx));
	bpf_probe_read(&size, sizeof(size), (void *)&PT_REGS_PARM2(ctx));

	val = bpf_map_lookup_elem(&my_map, &size);
	if (val && *val < UINT_MAX)
		*val = *val + 1;
	else
		bpf_map_update_elem(&my_map, &size, &count_start, BPF_NOEXIST);

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
