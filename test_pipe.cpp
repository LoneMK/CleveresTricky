#include <unistd.h>
#include <iostream>
#include <algorithm>

int main() {
    int fd[2];
    if (pipe(fd) < 0) return 1;

    char src[] = "hello";
    char dst[10] = {0};

    // This is checking if src is valid memory, simulating large IPC
    const size_t CHUNK_SIZE = 4096;
    size_t remaining = 5;
    size_t offset = 0;

    while (remaining > 0) {
        size_t to_copy = std::min(remaining, CHUNK_SIZE);
        ssize_t ret = write(fd[1], src + offset, to_copy);
        std::cout << "write ret: " << ret << std::endl;
        
        ret = read(fd[0], dst + offset, to_copy);
        std::cout << "read ret: " << ret << std::endl;
        
        offset += to_copy;
        remaining -= to_copy;
    }
    
    std::cout << "final dst: " << dst << std::endl;

    close(fd[0]);
    close(fd[1]);
    return 0;
}
