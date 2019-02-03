#ifndef STATUS_H
#define STATUS_H

#include <string>

namespace MyServer {
class Status {
  public:
    Status() noexcept : state_(nullptr) {}
    ~Status() { delete[] state_; }

    Status(const Status &);
    Status &operator=(const Status &);

    Status(Status &&rhs) noexcept : state_(rhs.state_) { rhs.state_ = nullptr; }
    Status &operator=(Status &&rhs) noexcept;

    static Status OK() { return Status(); }
    static Status NullPointer(const std::string &msg) {
        return Status(S_NullPointer, msg);
    }
    static Status NotSupported(const std::string &msg) {
        return Status(S_NotSupport, msg);
    }
    static Status IOError(const std::string &msg) {
        return Status(S_IOError, msg);
    }

    static Status SocketError(const std::string &msg) {
        return Status(S_SocketError, msg);
    }

    static Status HttpServerError(const std::string &msg) {
        return Status(S_HttpServerError, msg);
    }

    static Status LoopEventError(const std::string &msg) {
        return Status(S_LoopEventError, msg);
    }
    bool ok() const { return (code() == S_OK); }
    bool IsNullPointer() const { return code() == S_NullPointer; }
    bool IsNotSupported() const { return code() == S_NotSupport; }
    bool IsIOError() const { return code() == S_IOError; }
    bool IsSocketError() const { return code() == S_SocketError; }
    bool IsHttpServerError() const { return code() == S_HttpServerError; }
    bool IsLoopEventError() const { return code() == S_LoopEventError; }

    std::string ToString() const;

  private:
    const char *state_;
    enum Code {
        S_OK = 0,
        S_NullPointer,
        S_NotSupport,
        S_IOError,
        S_SocketError,
        S_HttpServerError,
        S_LoopEventError

    };
    Status(Code code, const std::string &msg);
    static const char *CopyState(const char *s);

    Code code() const {
        return (state_ == nullptr) ? S_OK : static_cast<Code>(state_[4]);
    }
};

inline Status::Status(const Status &rhs) {
    state_ = (rhs.state_ == nullptr) ? nullptr : CopyState(rhs.state_);
}

inline Status &Status::operator=(const Status &rhs) {
    if (state_ != rhs.state_) {
        delete[] state_;
        state_ = (rhs.state_ == nullptr) ? nullptr : CopyState(rhs.state_);
    }
    return *this;
}

inline Status &Status::operator=(Status &&rhs) noexcept {
    std::swap(state_, rhs.state_);
    return *this;
}

} // namespace MyServer

#endif /* STATUS_H */
