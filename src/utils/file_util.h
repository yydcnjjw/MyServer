#ifndef FILE_UTIL_H
#define FILE_UTIL_H

#include <sys/socket.h>

#include <memory>
#include <string>
#include <vector>

#include "error_util.h"

namespace Utils {

class FileError : public Error {
  public:
    FileError(const std::string &filename) : FileError(filename, "") {}
    FileError(const std::string &filename, const std::string &errortype)
        : Error("File Error"), filename(filename), errorType_(errortype) {}
    std::string filename;

  protected:
    virtual std::string format() override;

  private:
    std::string errorType_;
};

class FileNotFound : public FileError {
  public:
    FileNotFound(const std::string &filename)
        : FileError(filename, "Not Found") {}
};

class FileAgain : public FileError {
  public:
    FileAgain(const std::string &filename) : FileError(filename, "Again") {}
};

class SocketError : public Error {
  public:
    SocketError() : Error("Socket Error") {}
};

typedef int FileDesc;

enum class FileType {

};

class Directory {};

class File {
  public:
    File(const std::string &filename);
    File(FileDesc fileDesc);
    ~File();
    virtual VoidResult Create();
    virtual Result<bool> IsExist();
    virtual VoidResult Close();
    VoidResult Seek(const off_t, int whence);

    bool IsOpen();
    FileType GetFileType() const;
    std::string GetDir() const;
    std::string GetFileName() const;
    FileDesc GetFileDesc() const;

  protected:
    FileDesc filedesc_;
    std::string filename_;
    std::string dirname_;

  private:
    std::string dirname(const std::string &filename);
    FileType filetype_;
};

class MemFile : public File {
  public:
    MemFile(const std::string &filename);
    VoidResult Create() override;
    Result<bool> IsExist() override;
};

class Socket {
  public:
    Socket() = default;
    virtual ~Socket() = default;
    static Result<Socket *> NewSocket(const std::string &host,
                                      const std::string &serv);
    virtual VoidResult Bind() = 0;
    virtual VoidResult Listen() = 0;
    virtual VoidResult Connect() = 0;
    virtual Result<Socket *> Accept() = 0;
    virtual int GetFd() = 0;
    virtual VoidResult setNonBlocking() = 0;
};

// based buffer
class FileWriter {
  public:
    // TODO: writer mode append / trunc, creat ...
    FileWriter();
    FileWriter(const File &, bool append = false);
    FileWriter(const std::string &path, bool append = false);
    FileWriter(const FileDesc fileDesc);

    ~FileWriter();

    Result<FileDesc> getFd() const;
    Result<bool> IsOpen() const;
    VoidResult Append(const std::string &data);
    VoidResult Write(const char *, size_t size);
    VoidResult Write(const char);
    VoidResult Close();

    VoidResult Flush();
    VoidResult Sync();

  private:
    VoidResult append(const char *, size_t size);
    VoidResult flushBuffer();
    VoidResult writeUnbufferd(const char *data, size_t size);
    FileDesc file_desc_;
    std::shared_ptr<char> buf_;
    size_t pos_;
    Result<bool> is_open_;
};

// based buffer
class FileReader {
  public:
    FileReader(const File &file);
    FileReader(const std::string &path);
    FileReader(const FileDesc fileDesc);
    ~FileReader();

    Result<FileDesc> getFd() const;
    Result<bool> IsOpen() const;

    virtual Result<ssize_t> Read(char *, const size_t size);
    virtual Result<ssize_t> Read(char *);
    // virtual Result Read(char *, const size_t size, const ssize_t offset,
    // ssize_t *rsize);
    virtual VoidResult ReadLine(std::string &);
    VoidResult Skip(const size_t offset);
    VoidResult Close();

  private:
    Result<ssize_t> read(char *, size_t size);
    FileDesc file_desc_;
    std::shared_ptr<char> readbuf_;
    ssize_t readcnt_;
    char *readptr_;
    Result<bool> is_open_;
};

class MMapFileReader : public FileReader {
  public:
};
typedef uint IOEventFlag;
enum IOEvent { READ = 0x1, WRITE = 0x2 };

union PollData {
    FileDesc fd;
    void *ptr;
    uint32_t u32;
    uint64_t u64;
};

struct PollEvent {
    IOEventFlag event;
    PollData data;
};

typedef struct FdWatcher {
    int fd;
    IOEventFlag event;
    PollData data;
} FdWatcher;

enum IOPollBackend { EPOLL, SELECT, POLL };

class IOPoll {
  public:
    IOPoll() = default;
    virtual ~IOPoll() = default;
    static Result<IOPoll *> newIOPoll(IOPollBackend);
    virtual VoidResult InitIOPoll() = 0;
    virtual VoidResult Add(FdWatcher &) = 0;
    virtual VoidResult Modify(FdWatcher &) = 0;
    virtual VoidResult Delete(FdWatcher &) = 0;
    virtual VoidResult Poll(std::vector<PollEvent> &, int timeout) = 0;
};
} // namespace Utils

#endif /* FILE_UTIL_H */
