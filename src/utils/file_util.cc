#include "file_util.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cassert>
#include <cstdlib>
#include <cstring>

#include "string_util.h"

namespace Utils {

namespace {

constexpr FileDesc INVALID_FILE = -1;
constexpr const size_t FILE_BUFFER_SIZE = 64 * 1024;
constexpr const int LISTENQ = 1024;
constexpr const char *LISTENQ_ENV = "LISTENQ";

VoidResult FilePosixError(const std::string &filename = "",
                          const std::string &msg = "") {
    if (errno == ENONET) {
        return VoidResult::ErrorResult<FileNotFound>(msg, filename);
    } else if (errno == EAGAIN) {
        return VoidResult::ErrorResult<FileAgain>(msg, filename);
    }
    return VoidResult::ErrorResult<SysError>(msg, errno);
}

VoidResult SocketPosixError(const std::string &msg = "") {
    return VoidResult::ErrorResult<SocketError>(msg + ": " +
                                                std::strerror(errno));
}

void *Malloc(size_t size) {
    void *ptr = ::malloc(size);
    bzero(ptr, size);
    if (!ptr) {
        exit(-1);
    }
    return ptr;
}
class EPollIOPoll final : public IOPoll {
  public:
    EPollIOPoll() : nr_fdwatcher_(0) {}

    ~EPollIOPoll() override {}

    VoidResult InitIOPoll() override {
        epfd_ = epoll_create1(EPOLL_CLOEXEC);
        if (epfd_ < 0) {
            return FilePosixError("", "epoll_create1");
        }
        return VoidResult::OK();
    };

    VoidResult Add(FdWatcher &watchFD) override {
        nr_fdwatcher_++;
        return controlEPoll(EPOLL_CTL_ADD, watchFD);
    };

    VoidResult Modify(FdWatcher &watchFD) override {
        return controlEPoll(EPOLL_CTL_MOD, watchFD);
    };

    VoidResult Delete(FdWatcher &watchFD) override {
        nr_fdwatcher_--;
        return controlEPoll(EPOLL_CTL_DEL, watchFD);
    };

    VoidResult Poll(std::vector<PollEvent> &readyWatchFD,
                    int timeout) override {
        struct epoll_event *events = (struct epoll_event *)Malloc(
            sizeof(struct epoll_event) * nr_fdwatcher_);
        int nr_events = epoll_wait(epfd_, events, nr_fdwatcher_, timeout);
        if (nr_events < 0) {
            free(events);
            return FilePosixError("", "epoll wait");
        }
        PollEvent event;
        for (int i = 0; i < nr_events; i++) {
            uint32_t flag = events[i].events;
            event.event = 0;
            if (flag & (EPOLLIN | EPOLLRDNORM)) {
                event.event |= IOEvent::READ;
            }

            if (flag & (EPOLLOUT | EPOLLWRNORM)) {
                event.event |= IOEvent::WRITE;
            }

            memcpy(&event.data, &events[i].data, sizeof(PollData));
            if (event.event != 0) {
                readyWatchFD.push_back(event);
            }
        }
        free(events);
        return VoidResult::OK();
    };

  private:
    int epfd_;
    int nr_fdwatcher_;

    VoidResult controlEPoll(int controlflag, FdWatcher &watchFD) {
        struct epoll_event event;
        IOEventFlag eventflag = watchFD.event;
        if (controlflag != EPOLL_CTL_DEL) {
            event.events = 0;
            memcpy(&event.data, &watchFD.data, sizeof(PollData));
            if (eventflag & IOEvent::WRITE) {
                event.events |= (EPOLLOUT | EPOLLWRNORM);
            }

            if (eventflag & IOEvent::READ) {
                event.events |= (EPOLLIN | EPOLLRDNORM);
            }
        }

        int ret = epoll_ctl(epfd_, controlflag, watchFD.fd, &event);
        if (ret) {
            return FilePosixError("epoll_ctl");
        }
        return VoidResult::OK();
    }
};

// class SelectFDWatcher final : public FDWatcher {
//   public:
//     SelectFDWatcher() {}
// };

// class PollFDWatcher final : public FDWatcher {};

} // namespace

File::File(const std::string &filename)
    : filedesc_(-1), filename_(filename), dirname_(dirname(filename)) {}

File::File(FileDesc fileDesc)
    : filedesc_(fileDesc), filename_(""), dirname_("") {}

File::~File() {}

VoidResult File::Close() {
    if (IsOpen()) {
        if (-1 == ::close(filedesc_)) {
            return FilePosixError(filename_);
        }
    }
    return VoidResult::OK();
}

VoidResult File::Create() {
    if (IsOpen()) {
        return VoidResult::OK();
    }
    filedesc_ =
        ::creat(filename_.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (-1 == filedesc_) {
        return FilePosixError(filename_);
    }
    return VoidResult::OK();
}

bool File::IsExist(const std::string &filename) {
    if (-1 == ::access(filename.c_str(), F_OK)) {
        return false;
    }
    return true;
}

bool File::IsExist() {
    if (IsOpen()) {
        return true;
    }
    return IsExist(filename_);
}

VoidResult File::Seek(const off_t offset, int whence) {
    if (!IsOpen()) {
        return VoidResult::ErrorResult(new FileNotFound(filename_), "");
    }
    if (-1 == lseek(filedesc_, offset, whence)) {
        return FilePosixError(filename_);
    }
    return VoidResult::OK();
}

// TODO: use access check w r x permissions

std::string File::GetDir() const { return dirname_; }
std::string File::GetFileName() const { return filename_; }
Result<size_t> File::GetFileSize() const { return GetFileSize(filename_); }

Result<size_t> File::GetFileSize(const std::string &filename) {
    struct stat stat;
    if (-1 == ::stat(filename.c_str(), &stat)) {
        return FilePosixError(filename);
    }
    return stat.st_size;
}

FileDesc File::GetFileDesc() const { return filedesc_; }
std::string File::dirname(const std::string &filename) {
    std::string::size_type pos = filename.rfind('/');
    if (pos == std::string::npos) {
        return std::string(".");
    }
    return filename.substr(0, pos);
}

bool File::IsOpen() const { return -1 != filedesc_; }

MemFile::MemFile(const std::string &filename) : File(filename) {}

VoidResult MemFile::Create() {
    if (IsOpen()) {
        return VoidResult::OK();
    }
    filedesc_ = memfd_create(filename_.c_str(), MFD_CLOEXEC);
    if (-1 == filedesc_) {
        return FilePosixError(filename_);
    }
    return VoidResult::OK();
}

bool MemFile::IsExist() { return File::IsOpen(); }

class PosixSocket : public Socket {
  public:
    PosixSocket(int socketfd, struct sockaddr *sockaddr, socklen_t len)
        : socketfd_(socketfd), sockaddr_(sockaddr), socklen_(len) {}

    ~PosixSocket() override {
        ::free(sockaddr_);
        ::close(socketfd_);
    }

    VoidResult Bind() override {
        const int on = 1;
        ::setsockopt(socketfd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (-1 == ::bind(socketfd_, sockaddr_, socklen_)) {
            return SocketPosixError("bind");
        }
        return VoidResult::OK();
    }

    VoidResult Listen() override {
        char *ptr;
        int backlog = LISTENQ;
        if ((ptr = getenv(LISTENQ_ENV)) != NULL) {
            backlog = atoi(ptr);
        }
        if (listen(socketfd_, backlog) < 0) {
            return SocketPosixError("listen");
        }
        return VoidResult::OK();
    }

    VoidResult Connect() override {
        if (-1 == ::connect(socketfd_, sockaddr_, socklen_)) {
            return SocketPosixError("connect");
        }
        return VoidResult::OK();
    }

    Result<Socket *> Accept() override {
        Socket *connectSocket;
        struct sockaddr conSockaddr = {0};
        socklen_t len = sizeof(conSockaddr);
        int connectfd = accept(socketfd_, &conSockaddr, &len);
        if (connectfd == -1) {
            return SocketPosixError("accept");
        }
        struct sockaddr *addr = (struct sockaddr *)Malloc(len);
        ::memcpy(addr, &conSockaddr, len);
        connectSocket = new PosixSocket(connectfd, addr, len);
        if (connectSocket == nullptr) {
            return VoidResult::ErrorResult<OutOfMemory>();
        }
        return connectSocket;
    }

    VoidResult setNonBlocking() override {
        int flags;
        if (-1 == (flags = ::fcntl(socketfd_, F_GETFL))) {
            return SocketPosixError("fcntl F_GETFL");
        }
        if (-1 == ::fcntl(socketfd_, F_SETFL, flags | O_NONBLOCK)) {
            return SocketPosixError("fcntl F_SETFL");
        }
        return VoidResult::OK();
    }

    int GetFd() override { return socketfd_; }

  private:
    int socketfd_;
    struct sockaddr *sockaddr_;
    socklen_t socklen_;
};

Result<Socket *> Socket::NewSocket(const std::string &host,
                                   const std::string &serv) {
    struct addrinfo hints, *result;
    ::bzero(&hints, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    int ret;
    if (0 !=
        (ret = ::getaddrinfo(host.c_str(), serv.c_str(), &hints, &result))) {
        return SocketPosixError(gai_strerror(ret));
    }

    Socket *socketfd;
    int listenfd;
    for (auto rp = result; rp; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            listenfd =
                ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (listenfd < 0)
                continue;
        } else {
            continue;
        }

        struct sockaddr *addr;
        addr = (struct sockaddr *)Malloc(rp->ai_addrlen);
        ::memcpy(addr, rp->ai_addr, rp->ai_addrlen);
        socketfd = new PosixSocket(listenfd, addr, rp->ai_addrlen);
        if (socketfd == nullptr) {
            return VoidResult::ErrorResult<OutOfMemory>();
        }
        break;
    }

    freeaddrinfo(result);
    if (listenfd < 0) {
        return SocketPosixError("socket");
    }
    return socketfd;
};

FileWriter::FileWriter() : FileWriter(-1) {}

FileWriter::FileWriter(const File &file, bool append) : FileWriter() {
    if (file.IsOpen()) {
        file_desc_ = file.GetFileDesc();
        is_open_ = VoidResult::OK();
    } else {
        open(file.GetFileName(), append);
    }
}

FileWriter::FileWriter(const std::string &path, bool append) : FileWriter() {
    open(path, append);
}

FileWriter::FileWriter(const FileDesc fileDesc)
    : file_desc_(fileDesc), buf_(new char[FILE_BUFFER_SIZE]), pos_(0),
      rear_pos_(0) {
    if (fileDesc == -1) {
        is_open_ = VoidResult::ErrorResult(new FileNotFound(""));
    } else {
        is_open_ = VoidResult::OK();
    }
}

FileWriter::~FileWriter() { flushBuffer(); }

Result<FileDesc> FileWriter::getFd() const {
    if (!IsOpen().IsOK()) {
        return is_open_;
    }
    return file_desc_;
}

VoidResult FileWriter::IsOpen() const { return is_open_; }

Result<ssize_t> FileWriter::Append(const std::string &data) {
    return append(data.data(), data.size());
}

Result<ssize_t> FileWriter::Write(const char *buf, size_t size) {
    return append(buf, size);
}
Result<ssize_t> FileWriter::Write(const char ch) { return append(&ch, 1); }
VoidResult FileWriter::Close() {
    if (::close(file_desc_) == -1) {
        return FilePosixError();
    }
    return VoidResult::OK();
}

void FileWriter::open(const std::string &path, bool append) {
    if (append) {
        file_desc_ = ::open(path.c_str(), O_CREAT | O_WRONLY | O_APPEND,
                            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    } else {
        file_desc_ = ::open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC,
                            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    }

    if (-1 == file_desc_) {
        is_open_ = FilePosixError(path.c_str());
    }
    is_open_ = VoidResult::OK();
}

Result<ssize_t> FileWriter::append(const char *write_data, size_t write_size) {
    if (!IsOpen().IsOK()) {
        return is_open_;
    }

    size_t copy_size = std::min(write_size, FILE_BUFFER_SIZE - pos_);
    std::memcpy(buf_.get() + pos_, write_data, copy_size);
    write_data += copy_size;
    write_size -= copy_size;
    pos_ += copy_size;

    if (write_size == 0) {
        return Result<ssize_t>(copy_size, VoidResult::OK());
    }

    auto result = flushBuffer();
    if (!result.IsOK()) {
        return Result<ssize_t>(copy_size, result);
    }

    if (write_size < FILE_BUFFER_SIZE) {
        std::memcpy(buf_.get(), write_data, write_size);
        pos_ = write_size;
        return Result<ssize_t>(copy_size + write_size, VoidResult::OK());
    }

    Result<ssize_t> write_len = writeUnbufferd(write_data, write_size);
    if (!write_len.IsOK()) {
        if (write_len.IsError<FileAgain>()) {
            write_len.Get() += copy_size;
        }
        return write_len;
    }
    return VoidResult::OK();
}

VoidResult FileWriter::Flush() {
    if (!IsOpen().IsOK()) {
        return is_open_;
    }
    return flushBuffer();
}
VoidResult FileWriter::Sync() {
    if (!IsOpen().IsOK()) {
        return is_open_;
    }

    auto r = flushBuffer();
    if (r.IsOK() && ::fsync(file_desc_) != 0) {
        r = FilePosixError();
    }
    return r;
}

VoidResult FileWriter::flushBuffer() {
    Result<ssize_t> result;
    result = writeUnbufferd(buf_.get() + rear_pos_, pos_ - rear_pos_);
    if (!result.IsOK()) {
        if (result.IsError<FileAgain>()) {
            rear_pos_ += result.Get();
        }
        return result;
    }
    pos_ = 0;
    rear_pos_ = 0;
    return VoidResult::OK();
}

Result<ssize_t> FileWriter::writeUnbufferd(const char *data, size_t size) {
    ssize_t write_len = 0;
    while (size > 0) {
        ssize_t write_result = ::write(file_desc_, data, size);
        if (write_result < 0) {
            if (errno == EINTR)
                continue;
            return Result<ssize_t>(write_len, FilePosixError());
        }
        write_len += write_result;
        data += write_result;
        size -= write_result;
    }
    return VoidResult::OK();
}

FileReader::FileReader() : FileReader(-1) {}

FileReader::FileReader(const File &file) : FileReader() {
    if (file.IsOpen()) {
        file_desc_ = file.GetFileDesc();
        is_open_ = VoidResult::OK();
    } else {
        open(file.GetFileName());
    }
}

FileReader::FileReader(const std::string &path) : FileReader() { open(path); }
FileReader::FileReader(const FileDesc fileDesc)
    : file_desc_(fileDesc), readbuf_(new char[FILE_BUFFER_SIZE]), readcnt_(0),
      readptr_(readbuf_.get()) {
    if (fileDesc == -1) {
        is_open_ = VoidResult::ErrorResult(new FileNotFound(""));
    } else {
        is_open_ = VoidResult::OK();
    }
}

FileReader::~FileReader() {}

void FileReader::open(const std::string &path) {
    file_desc_ = ::open(path.c_str(), O_CREAT | O_RDONLY,
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    if (-1 == file_desc_) {
        is_open_ = FilePosixError(path.c_str());
    }
    is_open_ = VoidResult::OK();
}

Result<FileDesc> FileReader::getFd() const {
    if (!IsOpen().IsOK()) {
        return is_open_;
    }
    return file_desc_;
}
Result<bool> FileReader::IsOpen() const { return is_open_; }

Result<ssize_t> FileReader::Read(char *buf, const size_t size) {
    return read(buf, size);
}
Result<ssize_t> FileReader::Read(char *ch) { return read(ch, 1); }

// Result FileReader::Read(char *buf, size_t size, ssize_t offset,
//                         ssize_t *rsize) {
//     if (!IsOpen()) {
//         return isOpen_;
//     }
// again:
//     *rsize = ::pread(fileDesc_, buf, size, offset);
//     if (*rsize < 0) {
//         if (errno == EINTR) {
//             goto again;
//         }
//         return FilePosixError("");
//     }
//     return Result::OK();
// }

VoidResult FileReader::ReadLine(std::string &str) {
    char c;
    while (true) {
        Result<ssize_t> result = read(&c, 1);
        if (result.Get() == 1) {
            str.push_back(c);
            if (c == '\n')
                break;
        } else {
            return result;
        }
    }
    return VoidResult::OK();
}

VoidResult FileReader::Close() {
    if (::close(file_desc_) == -1) {
        return FilePosixError();
    }
    return VoidResult::OK();
}

Result<ssize_t> FileReader::read(char *buf, size_t size) {
    if (!IsOpen().IsOK()) {
        return is_open_;
    }

    ssize_t rsize = 0;
    while (size > 0) {
        if (readcnt_ <= 0) {
        again:
            readcnt_ = ::read(file_desc_, readbuf_.get(), FILE_BUFFER_SIZE);
            if (readcnt_ < 0) {
                if (errno == EINTR) {
                    goto again;
                }
                return Result<ssize_t>(rsize, FilePosixError());
            } else if (readcnt_ == 0) {
                return rsize;
            }
            readptr_ = readbuf_.get();
        }
        if (readcnt_ >= size) {
            memcpy(buf, readptr_, size);
            readptr_ += size;
            readcnt_ -= size;
            rsize += size;
            size = 0;
        } else {
            memcpy(buf, readptr_, readcnt_);
            buf += readcnt_;
            size -= readcnt_;
            rsize += readcnt_;
            readcnt_ = 0;
        }
    }
    return rsize;
}
VoidResult FileReader::Skip(const size_t offset) {
    if (static_cast<off_t>(-1) == ::lseek(file_desc_, offset, SEEK_CUR)) {
        return FilePosixError("");
    }
    return VoidResult::OK();
}

Result<IOPoll *> IOPoll::newIOPoll(IOPollBackend backend) {
    IOPoll *poll = nullptr;
    if (backend == IOPollBackend::EPOLL) {
        poll = new EPollIOPoll;
        if (poll == nullptr) {
            return VoidResult::ErrorResult<OutOfMemory>(
                "allocate IOPoll memory");
        }
        VoidResult result = poll->InitIOPoll();
        if (!result.IsOK()) {
            free(poll);
            return result;
        }
    } else {
        return VoidResult::ErrorResult<NotSupport>(
            "IOPoll is not support this backend");
    }
    return poll;
}

Result<FileCacheEntity> FileCache::FileGet(const std::string &key) {
    auto it = filemap_.find(key);
    if (it != filemap_.end()) {
        return it->second;
    }

    Result<size_t> file_size = File::GetFileSize(key);
    if (!file_size.IsOK()) {
        return FilePosixError(key);
    }
 
    if (file_size.Get() > option_.max_file_size ||
        CacheTotal() + file_size.Get() > option_.file_cache_apability) {
        return VoidResult::ErrorResult<FileCacheCapabilityError>();
    }

    int fd = ::open(key.c_str(), O_RDONLY);
    if (fd < 0) {
        return FilePosixError(key);
    }

    void *mmap_base =
        ::mmap(/*addr=*/nullptr, file_size.Get(), PROT_READ, MAP_SHARED, fd, 0);
    if (mmap_base == MAP_FAILED) {
        return Result<char *>(nullptr, FilePosixError(key));
    }

    cached_size_ += file_size.Get();

    FileCacheEntity entity;
    entity.data = static_cast<char *>(mmap_base);
    entity.size = file_size.Get();
    entity.fd = fd;
    filemap_.emplace(key, entity);
    return entity;
}

size_t FileCache::CacheTotal() const { return cached_size_; }

FileCache* GetFileCache() {
    static Singleton<FileCache> singletion;
    return singletion.get();
}

std::string FileError::format() {
    if (errorType_.empty()) {
        return string_format("%s:%s", error_.c_str(), filename.c_str());
    }
    return string_format("%s:%s:%s", error_.c_str(), errorType_.c_str(),
                         filename.c_str());
}

} // namespace Utils
