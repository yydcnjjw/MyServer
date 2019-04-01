#ifndef FILE_UTIL_H
#define FILE_UTIL_H

#include <sys/socket.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "common/singleton.h"
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

class File {
  public:
    File();
    File(const std::string &filename);
    File(FileDesc fileDesc);
    ~File();
    virtual VoidResult Create();
    static bool IsExist(const std::string &filename);
    virtual bool IsExist();
    virtual VoidResult Close();
    VoidResult Seek(const off_t, int whence);

    bool IsOpen() const;
    FileType GetFileType() const;
    std::string GetDir() const;
    std::string GetFileName() const;
    static Result<size_t> GetFileSize(const std::string &filename);
    Result<size_t> GetFileSize() const;

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
    bool IsExist() override;

  private:
    static bool IsExist(const std::string &filename);
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
    VoidResult IsOpen() const;
    Result<ssize_t> Append(const std::string &data);
    Result<ssize_t> Write(const char *, size_t size);
    Result<ssize_t> Write(const char);
    VoidResult Close();

    VoidResult Flush();
    VoidResult Sync();

  private:
    void open(const std::string &path, bool append);
    Result<ssize_t> append(const char *, size_t size);
    VoidResult flushBuffer();
    Result<ssize_t> writeUnbufferd(const char *data, size_t size);
    FileDesc file_desc_;
    std::shared_ptr<char[]> writebuf_;
    size_t pos_;
    size_t rear_pos_;
    VoidResult is_open_;
};

// based buffer
class FileReader {
  public:
    FileReader();
    FileReader(const File &file);
    FileReader(const std::string &path);
    FileReader(const FileDesc fileDesc);
    ~FileReader();

    Result<FileDesc> getFd() const;
    VoidResult IsOpen() const;

    virtual Result<ssize_t> Read(char *, const size_t size);
    virtual Result<ssize_t> Read(char *);
    // virtual Result Read(char *, const size_t size, const ssize_t offset,
    // ssize_t *rsize);
    virtual VoidResult ReadLine(std::string &);
    VoidResult Skip(const size_t offset);
    VoidResult Close();

  private:
    void open(const std::string &path);
    Result<ssize_t> read(char *, size_t size);
    FileDesc file_desc_;
    std::shared_ptr<char[]> readbuf_;
    ssize_t readcnt_;
    char *readptr_;
    VoidResult is_open_;
};

class MMapFileReader : public FileReader {
  public:
};
typedef uint IOEventFlag;
enum IOEvent { READ = 0x1, WRITE = 0x2, ERR = 0x4 };

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

typedef struct FileCacheOption {
    size_t max_file_size = 2 * 1024 * 1024;           // 2MB
    size_t file_cache_apability = 1024 * 1024 * 1024; // 1G
} FileCacheOption;
struct FileCacheEntity {
    char *data = nullptr;
    size_t size = 0;
    FileDesc fd = -1;
};

class FileCacheCapabilityError : public Error {
  public:
    FileCacheCapabilityError() : Error("File Cache Capability Error") {}
};

typedef std::map<std::string, FileCacheEntity> FileMap;
class FileCache {
  public:
    FileCache() : option_(FileCacheOption()), cached_size_(0) {}
    Result<FileCacheEntity> FileGet(const std::string &key);
    size_t CacheTotal() const;

    void SetOption(const FileCacheOption &option) { option_ = option; };

  private:
    FileMap filemap_;
    FileReader reader_;

    FileCacheOption option_;
    size_t cached_size_;
};

FileCache *GetFileCache();
} // namespace Utils

#endif /* FILE_UTIL_H */
