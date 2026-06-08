#include <unistd.h>
#include <iostream>

int main() {
    int fd[2];
    if (pipe(fd) < 0) return 1;

    char src[] = "hello";
    char dst[10] = {0};

    // This is checking if src is valid memory
    ssize_t ret = write(fd[1], src, 5);
    std::cout << "write ret: " << ret << std::endl;

    ret = read(fd[0], dst, 5);
    std::cout << "read ret: " << ret << ", dst: " << dst << std::endl;

    close(fd[0]);
    close(fd[1]);
    return 0;
}
