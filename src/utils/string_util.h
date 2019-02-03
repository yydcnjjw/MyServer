#ifndef STRING_UTIL_H
#define STRING_UTIL_H

#include <functional>
#include <memory>
#include <sstream>
#include <string>

namespace Utils {

template <typename... Args>
std::string string_format(const std::string &format, Args... args) {
    size_t size = std::snprintf(nullptr, 0, format.c_str(), args...) + 1;
    std::unique_ptr<char[]> buf(new char[size]);
    std::snprintf(buf.get(), size, format.c_str(), args...);
    return std::string(buf.get(), buf.get() + size - 1);
}

void string_split(const std::string &s, char delim,
                  std::function<void(const std::string &)> fn);

} // namespace Utils

#endif /* STRING_UTIL_H */
