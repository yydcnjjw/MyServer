#ifndef LOG_H
#define LOG_H

#include <string>

#include "utils/file_util.h"
#include "utils/error_util.h"

namespace Utils {

enum class LogLevel { DEBUG, INFO, WARN, ERROR };

struct LogOption {
    LogLevel outputLevel;
    std::string logfile;
};

class Log {
  public:
    Log(LogOption);
    ~Log();    

    VoidResult Debug(const std::string &);
    VoidResult Info(const std::string &);
    VoidResult WARN(const std::string &);
    VoidResult ERROR(const std::string &);

  private:
    VoidResult log(LogLevel, const std::string &);
    std::string getLabel(LogLevel level);
    FileWriter logfile_;
    LogLevel outputLevel_;
};

} // namespace MyHttpServer

#endif /* LOG_H */
