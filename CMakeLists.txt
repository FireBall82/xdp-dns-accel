cmake_minimum_required(VERSION 3.20)
project(net_accel_dns C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Removed -march=native to keep Nix happy
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBXDP REQUIRED libxdp)
pkg_check_modules(LIBURING REQUIRED liburing)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBXDP_INCLUDE_DIRS}
    ${LIBURING_INCLUDE_DIRS}
)

set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/bpf/xdp_filter.bpf.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/xdp_filter.bpf.o)

# Added `env HARDENING_DISABLE=all` to prevent Nix from injecting x86_64 hardening flags into the bpf compiler
add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND env HARDENING_DISABLE=all $ENV{CLANG} -g -O2 -target bpf 
            -D__TARGET_ARCH_x86 
            -I${CMAKE_CURRENT_SOURCE_DIR}/include 
            ${LIBBPF_CFLAGS}
            -c ${BPF_SRC} -o ${BPF_OBJ}
    COMMAND $ENV{LLVM_STRIP} -g ${BPF_OBJ}
    DEPENDS ${BPF_SRC}
    COMMENT "Building eBPF object ${BPF_OBJ}"
)

add_custom_target(bpf_target ALL DEPENDS ${BPF_OBJ})

# Build the C++ daemon
add_executable(dns_daemon src/main.cpp)

# Explicitly tell the daemon where to find shared_dns_table.hpp
target_include_directories(dns_daemon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Link everything
target_link_libraries(dns_daemon
    PRIVATE
    ${LIBBPF_LIBRARIES}
    ${LIBXDP_LIBRARIES}
    ${LIBURING_LIBRARIES}
    pthread
    rt
)

target_link_directories(dns_daemon PRIVATE 
    ${LIBBPF_LIBRARY_DIRS}
    ${LIBXDP_LIBRARY_DIRS}
    ${LIBURING_LIBRARY_DIRS}
)
