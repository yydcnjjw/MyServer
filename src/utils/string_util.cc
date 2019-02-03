#include "string_util.h"

#include <memory>

namespace Utils{
void string_split(const std::string &s, char delim,
                  std::function<void(const std::string &)> fn) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        fn(item);
    }
}

    
} // namespace MyServer
