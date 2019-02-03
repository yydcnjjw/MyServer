#include "error_util.h"

#include <cstring>

#include "string_util.h"

namespace Utils {

namespace {} // namespace

std::string Error::str(const std::string &msg) {
    if (msg.empty()) {
        return string_format("[%s]", format().c_str());
    }
    return string_format("[%s]\n%s", format().c_str(), msg.c_str());
}
std::string Error::format() { return error_; }

std::string SysError::format() {
    return string_format("%s:%d:%s", error_.c_str(), syserrcode,
                         std::strerror(syserrcode));
}

} // namespace Utils
