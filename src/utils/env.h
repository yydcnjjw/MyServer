#ifndef ENV_H
#define ENV_H

#include <vector>
#include "status.h"

namespace MyServer {
class Socket;
class WritableFile;
class IOPoll;
enum IOPollBackend { EPOLL, SELECT, POLL };
class Env {
  public:
    Env() = default;
    Env(const Env &) = delete;
    Env &operator=(const Env &) = delete;
    virtual ~Env() = default;
    static Env *Default();

    virtual Status newWritableFile(const std::string &fname,
                                   WritableFile **result) = 0;

    virtual bool FileExists(const std::string &fname) = 0;
    virtual Status newTcpSocket(const std::string &host,
                                const std::string &serv, Socket **socket) = 0;
    virtual Status newIOPoll(IOPollBackend backend, IOPoll **) = 0;
};

#define ENV Env::Default()

typedef uint IOEventFlag;
enum IOEvent { READ = 0x1, WRITE = 0x2 };

typedef struct FdWatcher {
    int fd;
    IOEventFlag event;
    void *data;
} FdWatcher;

class IOPoll {
  public:
    IOPoll() = default;
    IOPoll(const IOPoll &) = delete;
    IOPoll &operator=(const IOPoll &) = delete;
    virtual ~IOPoll() = default;
    virtual Status InitIOPoll() = 0;
    virtual Status Add(FdWatcher &) = 0;
    virtual Status Modify(FdWatcher &) = 0;
    virtual Status Delete(FdWatcher &) = 0;
    virtual Status Poll(std::vector<void *> &, int timeout) = 0;
};

class WritableFile {
  public:
    WritableFile() = default;
    WritableFile(const WritableFile &) = delete;
    WritableFile &operator=(const WritableFile &) = delete;
    virtual ~WritableFile() = default;

    virtual Status Append(const std::string &data) = 0;
    virtual Status Close() = 0;
    virtual Status Flush() = 0;
    virtual Status Sync() = 0;
};

class Socket {
  public:
    Socket() = default;
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;
    virtual ~Socket() = default;

    virtual Status Bind() = 0;
    virtual Status Listen() = 0;
    virtual Status Connect() = 0;
    virtual Status Accept(Socket **) = 0;
    virtual Status Close() = 0;
    virtual Status Read(char *, size_t *size) = 0;
    virtual Status ReadAll(char **data, int *size) = 0;
    virtual Status Write(const char *data, size_t size) = 0;
    virtual int GetFd() = 0;
    virtual Status setNonBlocking() = 0;
};

} // namespace MyServer

#endif /* ENV_H */
