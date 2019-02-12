#include "log.h"

#include <ctime>
#include <mutex>
#include <sstream>

namespace Utils {
namespace {
std::mutex mtx;

// output string what have special_char
const std::string output_special_char(const std::string &str) {
    std::string output;
    for (auto ch : str) {
        switch (ch) {
        case '\\':
            output.append("\\\\");
            break;
        case '\a':
            output.append("\\a");
            break;
        case '\b':
            output.append("\\b");
            break;
        case '\t':
            output.append("\\t");
            break;
        case '\n':
            output.append("\\n");
            break;
        case '\v':
            output.append("\\v");
            break;
        case '\f':
            output.append("\\f");
            break;
        case '\r':
            output.append("\\r");
            break;
        default:
            output.push_back(ch);
            break;
        }
    }
    return output;
}
} // namespace
Log::Log(LogOption option)
    : logfile_(option.logfile.empty() ? "LOG.log" : option.logfile),
      outputLevel_(option.outputLevel) {}
Log::~Log() {
    logfile_.Flush();    
}

VoidResult Log::Debug(const std::string &msg) {
    return log(LogLevel::DEBUG, msg);
}
VoidResult Log::Info(const std::string &msg) {
    return log(LogLevel::INFO, msg);
}
VoidResult Log::WARN(const std::string &msg) {
    return log(LogLevel::WARN, msg);
}
VoidResult Log::ERROR(const std::string &msg) {
    return log(LogLevel::ERROR, msg);
}

VoidResult Log::log(LogLevel level, const std::string &msg) {
    if (level < outputLevel_) {
        return VoidResult::OK();
    }

    std::stringstream format_msg;

    std::time_t t = std::time(nullptr);
    tm tm;
    {
        std::lock_guard<std::mutex> lock(mtx);
        tm = *std::localtime(&t);
    }

    char timebuf[33];
    strftime(timebuf, sizeof(timebuf), "[%Y-%m-%d %H:%M:%S]", &tm);
    format_msg << timebuf;

    std::string type = getLabel(level);
    format_msg << type << ": ";
    
    // TODO: std out
    // if (true) {
    // 	printf("%s%s\n", format_msg.str().c_str(), output_special_char(msg).c_str());
    // }

    format_msg << msg << "\n";
    return logfile_.Append(format_msg.str());
}

std::string Log::getLabel(LogLevel level) {
    std::string type;
    switch (level) {
    case LogLevel::DEBUG:
        type = "DEBUG";
        break;
    case LogLevel::INFO:
        type = "INFO";
        break;
    case LogLevel::WARN:
        type = "WARN";
        break;
    case LogLevel::ERROR:
        type = "ERROR";
        break;
    }
    return type;
}
} // namespace Utils
