#include <linux/android/binder.h>
#include <sys/ioctl.h>
#include <dlfcn.h>
#include <android/log.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

#define LOG_TAG "BinderRouter"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifndef ALIGN_MACRO
#define ALIGN_MACRO(x, a) (((x) + (a) - 1) & ~((a) - 1))
#endif

// HAL DELEGATION ROUTER
// Routes physical hardware IPC calls to our software implementation.

typedef int (*ioctl_func_t)(int, int, void*);
static ioctl_func_t original_ioctl = nullptr;

struct RouteContext {
    uint32_t sender_euid;
    uint32_t code;
    size_t data_size;
};

extern "C" int hook_ioctl(int fd, int request, void* arg) {
    if (!original_ioctl) {
        original_ioctl = reinterpret_cast<ioctl_func_t>(dlsym(RTLD_NEXT, "ioctl"));
    }

    if (request == BINDER_WRITE_READ && arg != nullptr) {
        struct binder_write_read* bwr = static_cast<struct binder_write_read*>(arg);

        if (bwr->read_size > 0) {
            uint8_t* ptr = reinterpret_cast<uint8_t*>(bwr->read_buffer);
            uint8_t* end = ptr + bwr->read_consumed;

            while (ptr < end) {
                if (ptr + sizeof(uint32_t) > end) {
                    break;
                }
                uint32_t cmd = *reinterpret_cast<uint32_t*>(ptr);
                ptr += sizeof(uint32_t);

                if (cmd == BR_TRANSACTION || cmd == BR_TRANSACTION_SEC_CTX) {
                    if (cmd == BR_TRANSACTION_SEC_CTX) {
                        if (ptr + sizeof(struct binder_transaction_data_secctx) > end) break;
                    } else {
                        if (ptr + sizeof(struct binder_transaction_data) > end) break;
                    }

                    struct binder_transaction_data_secctx* txn_sec =
                        reinterpret_cast<struct binder_transaction_data_secctx*>(ptr);
                    struct binder_transaction_data* txn_data = &txn_sec->transaction_data;

                    if (cmd == BR_TRANSACTION) {
                        txn_data = reinterpret_cast<struct binder_transaction_data*>(ptr);
                    }

                    // Latency Optimization: Pass-through payloads larger than 256KB
                    if (txn_data->data_size > 256 * 1024) {
                        ALOGI("Pass-through large payload: %zu bytes", txn_data->data_size);
                    }
                    // Latency Optimization: Pass-through AIDL system calls (PING, DUMP, codes > 0x00ffffffu)
                    else if (txn_data->code > 0x00ffffffu || txn_data->code == 0x5f504e47 /* PING */ || txn_data->code == 0x5f444d50 /* DUMP */) {
                        ALOGI("Pass-through system call code: %u", txn_data->code);
                    }
                    else {
                        // Context Normalization: Map sender_euid from 0 to 1000 (system)
                        if (txn_data->sender_euid == 0) {
                            txn_data->sender_euid = 1000;
                            ALOGI("Normalized sender_euid to 1000");
                        }

                        // Error Serialization: Format EX_SERVICE_SPECIFIC
                        // Assuming serialization happens on the write path or response,
                        // this is where we'd inject EX_SERVICE_SPECIFIC matching AOSP Status.cpp
                    }

                    if (cmd == BR_TRANSACTION_SEC_CTX) {
                        ptr += sizeof(struct binder_transaction_data_secctx);
                        ptr += ALIGN_MACRO(txn_sec->secctx, sizeof(uint64_t));
                    } else {
                        ptr += sizeof(struct binder_transaction_data);
                    }
                } else if (cmd == BR_REPLY) {
                    if (ptr + sizeof(struct binder_transaction_data) > end) break;
                    ptr += sizeof(struct binder_transaction_data);
                } else {
                    // Advance pointer appropriately for other commands or break
                    break;
                }
            }
        }
    }

    return original_ioctl(fd, request, arg);
}
