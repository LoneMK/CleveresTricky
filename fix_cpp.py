import os

cpp_file = "module/src/main/cpp/binder_interceptor.cpp"
with open(cpp_file, "r") as f:
    content = f.read()

import re

# We need to replace the entire block of safe_memcpy and its helpers
# Let's find the start of the section and the end of safe_memcpy
start_marker = "// Thread-local SIGSEGV recovery for safe_memcpy probing"
end_marker = "bool BinderStreamParser::safeRead(uintptr_t base, size_t offset, void *dst,"

# Find the block to replace
idx_start = content.find(start_marker)
idx_end = content.find(end_marker)

if idx_start != -1 and idx_end != -1:
    new_impl = """// Safe memory copy using pipe method (kernel validates pointer safely)
static bool safe_memcpy(void *dst, const void *src, size_t len) {
  if (len == 0) return true;
  if (dst == nullptr || src == nullptr) return false;

  int fd[2];
  if (pipe(fd) < 0) return false;

  // The kernel will safely return EFAULT if 'src' is an invalid pointer,
  // without raising a SIGSEGV in our process.
  ssize_t written = write(fd[1], src, len);
  if (written != (ssize_t)len) {
    close(fd[0]);
    close(fd[1]);
    return false;
  }

  // Read back into 'dst'
  ssize_t read_bytes = read(fd[0], dst, len);
  close(fd[0]);
  close(fd[1]);

  return read_bytes == (ssize_t)len;
}

"""
    new_content = content[:idx_start] + new_impl + content[idx_end:]
    with open(cpp_file, "w") as f:
        f.write(new_content)
    print("Replaced safe_memcpy")
else:
    print("Could not find markers")
