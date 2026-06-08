#include <sys/uio.h>
#include <unistd.h>

int main() {
    char src[] = "hello";
    char dst[10];
    struct iovec local_iov = { .iov_base = dst, .iov_len = 5 };
    struct iovec remote_iov = { .iov_base = src, .iov_len = 5 };
    process_vm_readv(getpid(), &local_iov, 1, &remote_iov, 1, 0);
    return 0;
}
