#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[32];
};

BPF_PERF_OUTPUT(events);

// kprobe to intercept file read operations in the Virtual File System
int kprobe__vfs_read(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count, loff_t *pos) {
    struct data_t data = {};
    
    // Get process ID and name
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Get filename from the file struct
    struct qstr d_name = file->f_path.dentry->d_name;
    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), d_name.name);

    // Filter: only capture events if the filename starts with "event"
    // Linux input devices are typically named event0, event1, event2, etc.
    if (data.filename[0] == 'e' && data.filename[1] == 'v' && 
        data.filename[2] == 'e' && data.filename[3] == 'n' && 
        data.filename[4] == 't') {
        
        // Send the data to userspace
        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
