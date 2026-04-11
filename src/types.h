#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <memory>
#include <chrono>

namespace msg {

using Bytes = std::vector<uint8_t>;
using UserId = int64_t;
using ChatId = int64_t;
using MessageId = int64_t;

struct Result {
    bool success = false;
    std::string error;

    static Result ok() { return {true, ""}; }
    static Result fail(const std::string& e) { return {false, e}; }
    explicit operator bool() const { return success; }
};

} // namespace msg
