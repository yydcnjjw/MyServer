#include "env.h"

#include <algorithm>
#include <vector>

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common/singleton.h"
#include "utils/log.h"

namespace MyServer {
namespace {

void *Malloc(size_t size) {
    void *ptr = ::malloc(size);
    bzero(ptr, size);
    if (!ptr) {
        exit(-1);
    }
    return ptr;
}

constexpr const size_t WritableFileBufferSize = 64 * 1024;
constexpr const int LISTENQ = 1024;
constexpr const char *LISTENQ_ENV = "LISTENQ";

Status PosixError(const std::string &context) {
    return Status::IOError(context + ": " + std::strerror(errno));
}
} // namespace

class EPollIOPoll final : public IOPoll {
  public:
    EPollIOPoll() : nr_fdwatcher(0) {}

    ~EPollIOPoll() override {}
    Status InitIOPoll() override {
        epfd_ = epoll_create1(EPOLL_CLOEXEC);
        if (epfd_ < 0) {
            return PosixError("epoll_create1");
        }
        return Status::OK();
    };

    Status Add(FdWatcher &watchFD) override {
        nr_fdwatcher++;
        return controlEPoll(EPOLL_CTL_ADD, watchFD);
    };

    Status Modify(FdWatcher &watchFD) override {
        return controlEPoll(EPOLL_CTL_MOD, watchFD);
    };

    Status Delete(FdWatcher &watchFD) override {
        nr_fdwatcher--;
        return controlEPoll(EPOLL_CTL_DEL, watchFD);
    };

    Status Poll(std::vector<void *> &readyWatchFD, int timeout) override {
        struct epoll_event *events;
        int nr_events = epoll_wait(epfd_, events, nr_fdwatcher, timeout);
        if (nr_events < 0) {
            free(events);
            return PosixError("epoll wait");
        }

        for (int i = 0; i < nr_events; i++) {
            readyWatchFD.push_back(events[i].data.ptr);
        }

        free(events);
        return Status::OK();
    };

  private:
    int epfd_;
    int nr_fdwatcher;
    Status controlEPoll(int controlflag, FdWatcher &watchFD) {
        struct epoll_event event;
        IOEventFlag eventflag = watchFD.event;
        if (controlflag != EPOLL_CTL_DEL) {
            event.data.ptr = watchFD.data;
            if (eventflag | IOEvent::WRITE) {
                event.events |= EPOLLOUT;
            }
            if (eventflag | IOEvent::READ) {
                event.events = EPOLLIN;
            }
        }

        int ret = epoll_ctl(epfd_, controlflag, watchFD.fd, &event);
        if (ret) {
            return PosixError("epoll_ctl");
        }

        return Status::OK();
    }
};

// class SelectFDWatcher final : public FDWatcher {
//   public:
//     SelectFDWatcher() {}
// };

// class PollFDWatcher final : public FDWatcher {};

class PosixWritableFile final : public WritableFile {
  public:
    PosixWritableFile(const std::string &filename, int fd)
        : fd_(fd), pos_(0), filename_(filename), dirname_(Dirname(filename_)) {}

    ~PosixWritableFile() override {
        if (fd_ >= 0) {
            Close();
        }
    }
    Status Append(const std::string &data) override {
        size_t write_size = data.size();
        const char *write_data = data.data();

        size_t copy_size = std::min(write_size, WritableFileBufferSize - pos_);
        ::memcpy(buf_, write_data, copy_size);
        write_data += copy_size;
        write_size -= copy_size;
        pos_ += copy_size;
        if (write_size == 0) {
            return Status::OK();
        }

        Status s = FlushBuffer();
        if (!s.ok()) {
            return s;
        }

        if (write_size < WritableFileBufferSize) {
            std::memcpy(buf_, write_data, write_size);
            pos_ = write_size;
            return Status::OK();
        }
        return WriteUnbuffered(write_data, write_size);
    }
    Status Close() override {
        Status s = FlushBuffer();
        int close_result = ::close(fd_);
        if (close_result < 0 && s.ok()) {
            s = PosixError(filename_);
        }
        fd_ = -1;
        return s;
    }
    Status Flush() override { return FlushBuffer(); }
    Status Sync() override {
        Status s = FlushBuffer();
        if (s.ok() && ::fsync(fd_) != 0) {
            return PosixError(filename_);
        }
        return s;
    }

  private:
    static std::string Dirname(const std::string &filename) {
        std::string::size_type pos = filename.rfind('/');
        if (pos == std::string::npos) {
            return std::string(".");
        }
        return filename.substr(0, pos);
    }

    Status FlushBuffer() {
        Status s = WriteUnbuffered(buf_, pos_);
        pos_ = 0;
        return s;
    }
    Status WriteUnbuffered(const char *data, size_t size) {
        while (size > 0) {
            ssize_t write_result = ::write(fd_, data, size);
            if (write_result < 0) {
                if (errno == EINTR)
                    continue;
                return PosixError(filename_);
            }
            data += write_result;
            size -= write_result;
        }
        return Status::OK();
    }

    int fd_;
    char buf_[WritableFileBufferSize];
    size_t pos_;

    const std::string filename_;
    const std::string dirname_;
};

class PosixSocket : public Socket {
  public:
    PosixSocket(int socketfd, struct sockaddr *sockaddr, socklen_t len)
        : socketfd_(socketfd), sockaddr_(sockaddr), socklen_(len) {}

    ~PosixSocket() override {
        free(sockaddr_);
        close(socketfd_);
    }

    Status Bind() override {
        const int on = 1;
        ::setsockopt(socketfd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (-1 == ::bind(socketfd_, sockaddr_, socklen_)) {
            return PosixError("bind");
        }
        return Status::OK();
    }

    Status Listen() override {
        char *ptr;
        int backlog = LISTENQ;
        if ((ptr = getenv(LISTENQ_ENV)) != NULL) {
            backlog = atoi(ptr);
        }
        if (listen(socketfd_, backlog) < 0) {
            return PosixError("listen");
        }
        return Status::OK();
    }

    Status Connect() override {
        if (-1 == ::connect(socketfd_, sockaddr_, socklen_)) {
            return PosixError("connect");
        }
        return Status::OK();
    }

    Status Accept(Socket **connectSocket) override {
        struct sockaddr conSockaddr = {0};
        socklen_t len = sizeof(conSockaddr);
        int connectfd = accept(socketfd_, &conSockaddr, &len);
        if (connectfd == -1) {
            return PosixError("accept");
        }
        struct sockaddr *addr = (struct sockaddr *)Malloc(len);
        ::memcpy(addr, &conSockaddr, len);
        *connectSocket = new PosixSocket(connectfd, addr, len);
        return Status::OK();
    }

    Status setNonBlocking() override {
        int flags;
        if (-1 == (flags = ::fcntl(socketfd_, F_GETFL))) {
            return PosixError("fcntl F_GETFL");
        }
        if (-1 == ::fcntl(socketfd_, F_SETFL, flags | O_NONBLOCK)) {
            return PosixError("fcntl F_SETFL");
        }
        return Status::OK();
    }

    Status Close() override {
        if (-1 == close(socketfd_)) {
            return PosixError("close");
        }
        return Status::OK();
    }

    Status Read(char *data, size_t *size) override {
        ssize_t nread;
    again:
        nread = ::read(socketfd_, data, *size);
        if (nread < 0) {
            if (errno == EINTR) {
                goto again;
            }
            return PosixError("socket read");
        }
        *size = nread;
        return Status::OK();
    }

    Status ReadAll(char **data, int *size) override {
        if (-1 == ::ioctl(socketfd_, FIONREAD, size)) {
            return PosixError("ioctl");
        }

        *data = (char *)Malloc(*size);
        ssize_t nread;
    again:
        nread = ::read(socketfd_, *data, *size);
        if (nread != *size) {
            if (errno == EINTR) {
                goto again;
            }
            return PosixError("socket read");
        }
        return Status::OK();
    }

    Status Write(const char *data, size_t size) override {
        ssize_t nwrite;
    again:
        nwrite = ::write(socketfd_, data, size);
        if (nwrite < 0) {
            if (errno == EINTR) {
                goto again;
            }
            return PosixError("socket write");
        }
        return Status::OK();
    }

    int GetFd() override { return socketfd_; }

  private:
    int socketfd_;
    struct sockaddr *sockaddr_;
    socklen_t socklen_;
};

class PosixEnv : public Env {
  public:
    PosixEnv(){};
    ~PosixEnv() override {
        static char msg[] =
            "PosivEnv singleton destroyed. Unsupported behavior!\n";
        std::fwrite(msg, 1, sizeof(msg), stderr);
        std::abort();
    }

    Status newWritableFile(const std::string &fname,
                           WritableFile **result) override {
        int fd = ::open(fname.c_str(), O_TRUNC | O_WRONLY | O_CREAT, 0644);
        if (fd < 0) {
            *result = nullptr;
            return PosixError(fname);
        }
        *result = new PosixWritableFile(fname, fd);
        return Status::OK();
    }

    bool FileExists(const std::string &fname) override {
        return ::access(fname.c_str(), F_OK) == 0;
    }

    Status newTcpSocket(const std::string &host, const std::string &serv,
                        Socket **socketfd) override {
        struct addrinfo hints, *result;
        ::bzero(&hints, sizeof(struct addrinfo));
        hints.ai_flags = AI_PASSIVE;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = 0;

        int ret;
        if (0 != (ret = ::getaddrinfo(host.c_str(), serv.c_str(), &hints,
                                      &result))) {
            return Status::SocketError(gai_strerror(ret));
        }

        *socketfd = nullptr;
        int listenfd;
        for (auto rp = result; rp; rp = rp->ai_next) {
            listenfd =
                ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (listenfd < 0)
                continue;

            struct sockaddr *addr;
            addr = (struct sockaddr *)Malloc(rp->ai_addrlen);
            ::memcpy(addr, rp->ai_addr, rp->ai_addrlen);
            *socketfd = new PosixSocket(listenfd, addr, rp->ai_addrlen);
            break;
        }

        freeaddrinfo(result);
        if (listenfd < 0) {
            return PosixError("socket");
        }
        return Status::OK();
    };

    Status newIOPoll(IOPollBackend backend, IOPoll **watcher) override {
        Status s;
        if (backend == IOPollBackend::EPOLL) {
            *watcher = new EPollIOPoll;
            s = (*watcher)->InitIOPoll();
            if (!s.ok()) {
                return s;
            }
        } else {
            *watcher = nullptr;
            return Status::NotSupported("fd watcher backend");
        }
        return Status::OK();
    }
};

Env *Env::Default() {
    static Singleton<PosixEnv> singleton;
    return singleton.get();
}
} // namespace MyServer
