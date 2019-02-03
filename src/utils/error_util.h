#ifndef ERROR_UTIL_H
#define ERROR_UTIL_H

#include <memory>
#include <string>

#include "misc_util.h"

namespace Utils {

class Error {
  public:
    Error() : Error("No Error") {}
    Error(const std::string &error) : error_(error) {}
    virtual ~Error() = default;
    std::string str(const std::string &msg);

  protected:
    virtual std::string format();
    std::string error_;
};

enum class Status { SUCCESS, FAILURE };

class VoidResult {
  public:
    VoidResult() : status_(Status::SUCCESS), error_(new Error) {}

    static VoidResult OK() { return VoidResult(); }

    template <typename ErrorType>
    static VoidResult ErrorResult(const std::string &msg = "") {
        return VoidResult(msg, new ErrorType);
    }

    static VoidResult ErrorResult(Error *error, const std::string &msg = "") {
        return VoidResult(msg, error);
    }

    bool IsOK() { return status_ == Status::SUCCESS; }

    template <typename Class> bool IsError() {
        return instanceof <Class>(error_.get());
    }

    std::string str() { return error_->str(msg_); };

  private:
    VoidResult(const std::string &msg, Error *e)
        : status_(Status::FAILURE), error_(e), msg_(msg) {}

    std::shared_ptr<Error> error_;
    Status status_;
    std::string msg_;
};

template <typename Value> class Result : public VoidResult {
  public:
    Result() = default;
    Result(Value value) : value_(value) {}
    template <typename Type>
    Result(const Result<Type> &result) : VoidResult(result) {}
    Result(const VoidResult &result) : VoidResult(result) {}

    Result(Value value, const VoidResult &result)
        : VoidResult(result), value_(value) {}

    Value &Get() { return value_; }

  private:
    Value value_;
};

class SysError : public Error {
  public:
    SysError(int errcode) : Error("System Error"), syserrcode(errcode) {}
    int syserrcode;

  protected:
    std::string format() override;
};
class NullPointer : public Error {
  public:
    NullPointer() : Error("Null Pointer") {}
};

class NotSupport : public Error {
  public:
    NotSupport() : Error("Not Support") {}
};
class OutOfMemory : public Error {
  public:
    OutOfMemory() : Error("Out of memory") {}
};

} // namespace Utils
#endif /* ERROR_UTIL_H */
