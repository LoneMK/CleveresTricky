#pragma once

#include <utility>
#include "cleverestricky_cbor_cose.h"

namespace cleveres {
namespace tricky {

/**
 * @brief RAII wrapper for RustBuffer to guarantee memory safety.
 *
 * This class takes ownership of a RustBuffer and automatically calls
 * rust_free_buffer() when it goes out of scope. It deletes the copy
 * constructor and copy assignment operator to prevent double-frees,
 * while implementing move semantics safely.
 */
class SafeRustBuffer {
public:
    // Takes ownership of the provided RustBuffer
    explicit SafeRustBuffer(RustBuffer buf) : buffer_(buf) {}

    // Destructor automatically frees the RustBuffer
    ~SafeRustBuffer() {
        if (buffer_.data != nullptr) {
            rust_free_buffer(buffer_);
            buffer_.data = nullptr;
            buffer_.len = 0;
        }
    }

    // Delete copy constructor and assignment
    SafeRustBuffer(const SafeRustBuffer&) = delete;
    SafeRustBuffer& operator=(const SafeRustBuffer&) = delete;

    // Move constructor
    SafeRustBuffer(SafeRustBuffer&& other) noexcept : buffer_(other.buffer_) {
        other.buffer_.data = nullptr;
        other.buffer_.len = 0;
    }

    // Move assignment
    SafeRustBuffer& operator=(SafeRustBuffer&& other) noexcept {
        if (this != &other) {
            if (buffer_.data != nullptr) {
                rust_free_buffer(buffer_);
            }
            buffer_ = other.buffer_;
            other.buffer_.data = nullptr;
            other.buffer_.len = 0;
        }
        return *this;
    }

    // Accessors
    const uint8_t* data() const { return buffer_.data; }
    uint8_t* data() { return buffer_.data; }
    size_t len() const { return buffer_.len; }
    bool is_empty() const { return buffer_.data == nullptr || buffer_.len == 0; }

    // Release ownership (if needed to pass back to C/Rust)
    RustBuffer release() {
        RustBuffer temp = buffer_;
        buffer_.data = nullptr;
        buffer_.len = 0;
        return temp;
    }

private:
    RustBuffer buffer_;
};

} // namespace tricky
} // namespace cleveres
