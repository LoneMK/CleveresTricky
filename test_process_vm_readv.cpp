#include <sys/uio.h>
#include <unistd.h>
#include <iostream>

int main() {
    int src = 42;
    int dst = 0;
    struct iovec local_iov = { .iov_base = &dst, .iov_len = sizeof(dst) };
    struct iovec remote_iov = { .iov_base = &src, .iov_len = sizeof(src) };

    ssize_t ret = process_vm_readv(getpid(), &local_iov, 1, &remote_iov, 1, 0);
    std::cout << "ret: " << ret << ", dst: " << dst << std::endl;
    return 0;
}
