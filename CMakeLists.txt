cmake_minimum_required(VERSION 3.11.0)
project(learn_bpf VERSION 0.1.0)

find_package(cxxopts REQUIRED)
find_package(fmt REQUIRED)
find_package(range-v3 REQUIRED)
find_package(Clang REQUIRED)
execute_process(COMMAND uname -r OUTPUT_VARIABLE arch OUTPUT_STRIP_TRAILING_WHITESPACE)

set(LINUX_SOURCE /lib/modules/${arch}/build/)
# set(CMAKE_C_FLAGS "${LINUX_SOURCE}tools/bpf/resolve_btfids/libbpf/libbpf.a")
message(${LINUX_SOURCE})
function(bpf prefix)
add_custom_target(${prefix}_bpf ALL
            # OUTPUT ${prefix}.ll ${prefix}.o
            COMMAND ${CLANG_INCLUDE_DIRS}/../bin/clang -S -nostdinc -I${LINUX_SOURCE}/arch/x86/include -I${LINUX_SOURCE}/arch/x86/include/uapi -I${LINUX_SOURCE}/arch/x86/include/generated -I${LINUX_SOURCE}/arch/x86/include/generated/uapi -I${LINUX_SOURCE}/include -I${LINUX_SOURCE}/include/uapi -I${LINUX_SOURCE}/include/generated/uapi -I${LINUX_SOURCE}/tools/testing/selftests/bpf -include ${LINUX_SOURCE}/include/linux/kconfig.h -Werror -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__ -D__TARGET_ARCH_x86 -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-tautological-compare -Wno-unknown-warning-option -Wno-address-of-packed-member -O2 -g -emit-llvm -c ${CMAKE_SOURCE_DIR}/${prefix}_kern.c -o ${CMAKE_BINARY_DIR}/${prefix}.ll
            COMMAND ${CLANG_INCLUDE_DIRS}/../bin/llc -march=bpf -filetype=obj -o ${CMAKE_BINARY_DIR}/${prefix}_kern.o ${CMAKE_BINARY_DIR}/${prefix}.ll
    )
    add_dependencies(learn_bpf ${prefix}_bpf)
endfunction()
add_executable(learn_bpf memcpy_kprobe_user.c bpf_load.c ./bpf/bpf.c)
target_link_libraries(learn_bpf PRIVATE elf)
include_directories(./bpf)
include_directories(./)
bpf(memcpy_kprobe)
