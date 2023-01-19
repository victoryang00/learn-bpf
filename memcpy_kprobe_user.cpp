#include "bpf_load.h"
#include "libbpf.h"
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"

#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <thread>

class ThreadSafeMap {
public:
    ThreadSafeMap() = default;

    // Multiple threads/readers can read the Map's value at the same time.
    std::map<unsigned long, std::tuple<unsigned long, unsigned long long int>> get() const {
        std::shared_lock lock(mutex_);
        return res;
    }

    // Only one thread/writer can increment/write the Map's value.
    void insert(unsigned long address, unsigned long size, unsigned long long time) {
        std::unique_lock lock(mutex_);
        res[address] = std::make_tuple(size, time);
    }

    // Only one thread/writer can reset/write the Map's value.
    void reset() {
        std::unique_lock lock(mutex_);
        res.clear();
    }

private:
    mutable std::shared_mutex mutex_;
    std::map<unsigned long, std::tuple<unsigned long, unsigned long long>> res;
};

void write_trace_to_map(ThreadSafeMap &map) {
    std::ifstream fp(DEBUGFS "trace_pipe");
    int i;
    int size;
    unsigned long address;
    unsigned long long time;
    std::string line;
    while (std::getline(fp, line)) {
        if (line.size() > 50) {
            i = std::sscanf(line.substr(51, 57).c_str(),
                            "bpf_trace_printk: munmap %d %lu %llu", &size, &address,
                            &time);
            std::cout << line.substr(51, 57).c_str() << " " << i << std::endl;
            if (i > 1) {
                map.insert(address, size, time);
                std::cout << address << " " << size << " " << time << std::endl;
            }
        }
    }
}

int main(int argc, char **argv) {

    auto map = ThreadSafeMap();
    std::map<uint64_t, uint64_t> addr_map;
    if (load_bpf_file("./memcpy_kprobe_kern.o") != 0) {
        printf("%s", bpf_log_buf);
        return 1;
    }
    std::jthread thr{[&] { write_trace_to_map(map); }};
    auto res = map.get();
    for (auto r: res) {
        //mode map
        std::cout << r.first << " " << std::get<0>(r.second) << " " << std::get<1>(r.second) << std::endl;
        for (int i = 0; i < std::get<0>(r.second); i += 64) {
            addr_map[r.first + i] = std::get<1>(r.second);
        }
    }
    map.reset();
    return 0;
}
