#include "http_server.h"

#include <unistd.h>

#include <filesystem>
#include <regex>

#include "core/event_listener.h"
#include "core/event_loop.h"
#include "utils/file_util.h"
#include "utils/log.h"
#include "utils/string_util.h"

namespace MyServer {
namespace {

namespace fs = std::filesystem;

const char *HTTP_V1_1 = "HTTP/1.1";
enum HTTP_STATUS { OK = 0, CONNECT = 1 };

const char *GET = "GET";
const char *POST = "POST";
const char *PUT = "PUT";
// const char *CONNECT = "connect";

const char *CONTENT_LENGTH = "Content-Length";
const char *CONTENT_TYPE = "Content-Type";

typedef std::vector<HttpHandler> HttpHandlers;
class HttpAgain : public HttpError {
  public:
    HttpAgain() {}
};
class HttpServerImpl;

class HttpServerResponseListener : public Listener {
  public:
    HttpServerResponseListener(Socket *serverSocket, HttpServerImpl *server)
        : server_socket_(serverSocket), server_(server) {}

    ~HttpServerResponseListener() override{

    };
    void Callback(EventLoop *loop) override;

  private:
    Socket *server_socket_;
    HttpServerImpl *server_;
};

class HttpServerImpl : public HttpServer {
  public:
    // TODO: current dir use absolute
    HttpServerImpl(const HttpServerOption &option)
        : option(option), server_socket_(nullptr), loop_(nullptr),
          server_iolistener_(nullptr), isStart_(false) {}
    ~HttpServerImpl() override {
        if (server_socket_ != nullptr) {
            delete server_socket_;
        }
        if (loop_ != nullptr) {
            delete loop_;
        }
    };

    VoidResult ApplyOption() {
        VoidResult result = listen_socket(option.host, option.port);
        if (!result.IsOK()) {
            return result;
        }

        result = check_root_dir();
        if (!result.IsOK()) {
            return result;
        }
        return VoidResult::OK();
    }

    HttpServer *Get(const std::string &re, HttpHandleFunc func) override {
        method_handlers[GET].push_back({std::regex(re), func});
        return this;
    }
    HttpServer *Post(const std::string &re, HttpHandleFunc func) override {
        method_handlers[POST].push_back({std::regex(re), func});
        return this;
    }

    VoidResult Start() override {
        if (loop_ == nullptr) {
            LogOption option;
            option.logfile = "Http.LOG";
            option.outputLevel = LogLevel::DEBUG;
            auto result = EventLoop::NewEventLoop(option);

            if (!result.IsOK()) {
                return result;
            }
            loop_ = result.Get();
        }

        if (isStart_) {
            return VoidResult::OK();
        }
        isStart_ = true;
        auto result = addToEventLoop(loop_);
        if (!result.IsOK()) {
            return result;
        }
        loop_->Run();
        return VoidResult::OK();
    }

    VoidResult Stop() override {
        VoidResult s;
        if (!isStart_) {
            return VoidResult::OK();
        }

        isStart_ = false;
        return VoidResult::OK();
    }
    VoidResult Restart() override { return VoidResult::OK(); }

    VoidResult addToEventLoop(EventLoop *loop) override {
        if (server_iolistener_ == nullptr) {
            server_iolistener_ =
                new HttpServerResponseListener(server_socket_, this);
            if (server_iolistener_ == nullptr) {
                return VoidResult::ErrorResult<OutOfMemory>();
            }
        }

        return loop->AddListener(server_socket_->GetFd(), IOEvent::READ,
                                 server_iolistener_);
    }
    HttpServerOption option;
    std::map<std::string, HttpHandlers> method_handlers;

  private:
    VoidResult listen_socket(const std::string &host, const std::string &port) {
        auto result = Socket::NewSocket(host, port);
        if (!result.IsOK()) {
            return result;
        }
        server_socket_ = result.Get();

        server_socket_->setNonBlocking();
        result = server_socket_->Bind();
        if (!result.IsOK()) {
            return result;
        }
        return server_socket_->Listen();
    }

    VoidResult check_root_dir() {
        std::string &root_dir = option.root_dir;
        try {
            const fs::path path = fs::absolute(root_dir);
            root_dir.assign(path);
            if (!fs::exists(path) || !fs::is_directory(path)) {
                return VoidResult::ErrorResult<HttpError>(
                    "root dir is invalid!");
            }
        } catch (fs::filesystem_error &e) {
            return VoidResult::ErrorResult<HttpError>(e.what());
        }
        return VoidResult::OK();
    }

    Socket *server_socket_;
    EventLoop *loop_;

    std::vector<HttpHandler> http_handles_;

    HttpServerResponseListener *server_iolistener_;
    bool isStart_;
};

// TODO: file cache system
size_t MAX_FILE_READ_SIZE = 4 * 1024;
class HttpRequestWriteListener : public Listener {
  public:
    HttpRequestWriteListener(Socket *connectSocket, HttpServerImpl *server,
                             HttpRequest *req, HttpResponse *res)
        : server_(server), connect_socket_(connectSocket), req_(req), res_(res),
          data_ptr_(nullptr), progress_(0),
          file_writer_(FileWriter(connectSocket->GetFd())), log_(nullptr),
          status_(Status::handle_message), filecache_(GetFileCache()),
          filesize_(0), write_progress_(0) {}

    ~HttpRequestWriteListener() override {
        delete connect_socket_;
        delete req_;
        delete res_;
    };

    void Callback(EventLoop *loop) override {
        if (log_ == nullptr) {
            log_ = loop->LOG();
        }
        VoidResult result;

        while (status_ != Status::finish) {
            switch (status_) {
            case Status::handle_message: {
                result = handle_message();
                break;
            }
            case Status::write_header: {
                result = write_header();
                break;
            }
            case Status::write_body: {
                result = write_body();
                break;
            }
            default:
                break;
            }

            if (!result.IsOK()) {
                if (result.IsError<HttpAgain>()) {
                    return;
                }
                reader_.Close();
                // TODO: Log socket info
                log_->ERROR("" + result.str());
                break;
            }
        }

        log_->Debug("");
        loop->RemoveListener(connect_socket_->GetFd(), IOEvent::WRITE);
        delete this;
    }

  private:
    VoidResult handle_message() {
        MultipartFiles &multipartfiles = res_->files;
        if (multipartfiles.empty()) {
            res_->headers.emplace(CONTENT_LENGTH,
                                  std::to_string(res_->body.size()));
        } else if (multipartfiles.size() == 1) {
            File *file = multipartfiles.begin()->second.file;
            auto filesize = file->GetFileSize();
            if (!filesize.IsOK()) {
                return filesize;
            }
            res_->headers.emplace(CONTENT_LENGTH,
                                  std::to_string(filesize.Get()));
            filesize_ = filesize.Get();
            if (filesize_ > 2 * 1024 * 1024) { // TODO: const variance
                reader_ = FileReader(*file);
            }
            log_->Debug(file->GetFileName());
        } else {
            return VoidResult::ErrorResult<HttpError>(
                "not support response multipartfiles");
        }
        // res_->headers.emplace(CONTENT_TYPE, "text/html");
        status_ = Status::write_header;
        return VoidResult::OK();
    }

    VoidResult write_header() {
        if (data_ptr_ == nullptr) {
            data_ptr_ = res_->GetResponseHeader();
        }
        auto result = write_len(data_ptr_->data(), data_ptr_->size());
        if (!result.IsOK()) {
            return result;
        }
        log_->Debug(*data_ptr_);
        delete data_ptr_;
        data_ptr_ = nullptr;
        status_ = Status::write_body;
        return VoidResult::OK();
    }

    VoidResult write_body() {
        if (!res_->body.empty()) {
            auto result = write_len(res_->body.data(), res_->body.size());
            if (!result.IsOK()) {
                return result;
            }
        } else {
            MultipartFiles &multipartfiles = res_->files;
            File *file = multipartfiles.begin()->second.file;
            auto cache_entity = filecache_->FileGet(file->GetFileName());
            if (!cache_entity.IsOK() &&
                cache_entity.IsError<FileCacheCapabilityError>()) {
                std::string buf;
                buf.assign(0, MAX_FILE_READ_SIZE);
                while (write_progress_ < filesize_) {
                    auto result = reader_.Read(&buf[0], MAX_FILE_READ_SIZE);
                    if (!result.IsOK()) {
                        return result;
                    }

                    auto write_size = write_len(buf.data(), result.Get());
                    write_progress_ += result.Get();
                    if (!write_size.IsOK()) {
                        return write_size;
                    }
                }
            } else {
                FileCacheEntity &entity = cache_entity.Get();
                auto write_size = write_len(entity.data, entity.size);
                if (!write_size.IsOK()) {
                    return write_size;
                }
		write_progress_ += entity.size;
            }
        }

	reader_.Close();
        auto result = file_writer_.Flush();
        if (!result.IsOK()) {
            if (result.IsError<FileAgain>()) {
                return VoidResult::ErrorResult<HttpAgain>("http write again!");
            }
        }

        log_->Debug(string_format("write progress = %d", write_progress_));

        status_ = Status::finish;
        return VoidResult::OK();
    }

    VoidResult write_len(const char *data, size_t len) {
        Result<ssize_t> result;
        if (write_buf_.empty()) {
            result = file_writer_.Write(data, len);
        } else {
            write_buf_.append(data, len);
            result = file_writer_.Write(write_buf_.data(), write_buf_.size());
        }
        if (!result.IsOK()) {
            if (result.IsError<FileAgain>()) {
                if (write_buf_.empty()) {
                    write_buf_.append(data + result.Get(), len - result.Get());
                } else {
                    write_buf_.erase(0, result.Get());
                }
                return VoidResult::ErrorResult<HttpAgain>("http write again!");
            }
            return result;
        }
        write_buf_.clear();
        return VoidResult::OK();
    }

    HttpServerImpl *server_;
    Socket *connect_socket_;
    HttpRequest *req_;
    HttpResponse *res_;

    std::string *data_ptr_;

    std::string buf_;
    size_t progress_;

    FileWriter file_writer_;
    Log *log_;

    enum class Status {
        handle_message,
        write_header,
        write_body,
        finish,
    };
    Status status_;

    FileCache *filecache_;

    FileReader reader_;
    std::string write_buf_;
    size_t filesize_;
    size_t write_progress_;
};

class HttpRequestReadListener : public Listener {
  public:
    HttpRequestReadListener(Socket *connectSocket, HttpServerImpl *server)
        : server_(server), connect_socket_(connectSocket),
          req_(new HttpRequest), res_(new HttpResponse),
          reader_(FileReader(connect_socket_->GetFd())), log_(nullptr),
          parse_status_(ParseStatus::request_line), buf_progress_(0),
          body_progress_(0) {}

    ~HttpRequestReadListener() override{};

    void Callback(EventLoop *loop) override {
        if (log_ == nullptr) {
            log_ = loop->LOG();
        }
        FileDesc fd = connect_socket_->GetFd();
        VoidResult result = handle_request(loop);

        if (!result.IsOK()) {
            if (result.IsError<HttpAgain>()) {
                return;
            }
            // TODO: Log socket info
            log_->ERROR("" + result.str());
            res_->status = 400;
        }

        Listener *listener =
            new HttpRequestWriteListener(connect_socket_, server_, req_, res_);
        loop->AddListener(fd, IOEvent::WRITE, listener);
        loop->RemoveListener(fd, IOEvent::READ);
        delete this;
    }

  private:
    VoidResult handle_request(EventLoop *loop) {
        VoidResult result;

        res_->version = HTTP_V1_1;
        res_->status = -1;

        while (parse_status_ != ParseStatus::finish) {
            switch (parse_status_) {
            case ParseStatus::request_line: {
                result = parse_request_line();
                break;
            }
            case ParseStatus::request_headers: {
                result = parse_headers();
                break;
            }
            case ParseStatus::post_query: {
                result = parse_post_query();
                break;
            }
            case ParseStatus::multipart_read_header: {
                result = parse_multipart_formdata_header();
                break;
            }
            case ParseStatus::multipart_read_file: {
                result = parse_multipart_formdata_file();
                break;
            }
            case ParseStatus::route: {
                route_handle();
                break;
            }
            default:
                break;
            }
            if (!result.IsOK()) {
                break;
            }
        }
        return result;
    }

    VoidResult parse_request_line() {
        std::string request_line;
        VoidResult result = read_line(request_line);
        if (!result.IsOK()) {
            return result;
        }

        log_->Debug(request_line);
        static std::regex re("(GET|HEAD|POST|PUT|DELETE|OPTIONS) "
                             "(([^?]+)(?:\\?(.+?))?) (HTTP/1\\.[01])\r\n");

        std::cmatch m;
        if (std::regex_match(request_line.data(), m, re)) {
            req_->method = std::string(m[1]);
            req_->target = std::string(m[2]);
            req_->path = std::string(m[3]);

            auto len = std::distance(m[4].first, m[4].second);
            if (len > 0) {
                parse_query_text(m[4], req_->params);
            }
            req_->version = std::string(m[5]);
            parse_status_ = ParseStatus::request_headers;
            return VoidResult::OK();
        }
        return VoidResult::ErrorResult<HttpError>("parse request line fail!");
    }

    void parse_query_text(const std::string &s, Params &params) {
        string_split(s, '&', [&](const std::string &query_field) {
            std::string key;
            std::string value;
            string_split(query_field, '=', [&](const std::string &kv) {
                if (key.empty()) {
                    key.assign(kv);
                } else {
                    value.assign(kv);
                }
            });
            params.emplace(key, value);
        });
    }

    VoidResult parse_headers() {
        static std::regex re(R"((.+?):\s*(.+?)\s*\r\n)");
        std::string header_line;
        VoidResult result;

        for (;;) {
            result = read_line(header_line);
            if (!result.IsOK()) {
                return result;
            }
            log_->Debug(header_line);
            if (!header_line.compare("\r\n")) {
                break;
            }
            std::cmatch m;
            if (std::regex_match(header_line.data(), m, re)) {
                auto key = std::string(m[1]);
                auto val = std::string(m[2]);
                req_->headers.emplace(key, val);
            }
            header_line.clear();
        }

        if (req_->method == POST || req_->method == PUT) {
            auto content_type =
                get_header_value_string(req_->headers, CONTENT_TYPE);
            if (!content_type.IsOK()) {
                return content_type;
            }
            if (!content_type.Get().find("multipart/form-data")) {
                parse_status_ = ParseStatus::multipart_read_header;
            } else if (!content_type.Get().find(
                           "application/x-www-form-urlencoded")) {
                parse_status_ = ParseStatus::post_query;
            }
        } else {
            parse_status_ = ParseStatus::route;
        }
        return VoidResult::OK();
    }

    VoidResult parse_post_query() {
        VoidResult result;
        auto content_length =
            get_header_value_int(req_->headers, CONTENT_LENGTH);

        if (!result.IsOK()) {
            return result;
        }

        std::string body;
        body.assign(content_length.Get(), 0);
        if (content_length.IsOK() && content_length.Get() > 0) {
            result = read_len(&body[0], content_length.Get());
        } else {
            // TODO: chunked
            result = read_content_without_length();
        }

        if (!result.IsOK()) {
            return result;
        }
        parse_query_text(body, req_->params);
        parse_status_ = ParseStatus::route;
        return VoidResult::OK();
    }

    VoidResult parse_multipart_formdata_header() {
        VoidResult result;
        static std::regex re_content_type("Content-Type: (.*?)\r\n",
                                          std::regex_constants::icase);
        static std::regex re_content_disposition(
            "Content-Disposition: form-data; name=\"(.*?)\"(?:; "
            "filename=\"(.*?)\")?\r\n",
            std::regex_constants::icase);

        std::string &body_content = multipart_data_buf_;
        std::string header_line;
        MultipartFileInfo &fileinfo = multipart_file_info_;
        for (;;) {
            if (body_content.empty()) {
                result = read_line(header_line);
                if (!result.IsOK()) {
                    return result;
                }
                body_progress_ += header_line.size();
            } else {
                auto pos = body_content.find('\n');
                if (pos == std::string::npos) {
                    header_line.append(body_content);
                    result = read_line(header_line);
                    if (!result.IsOK()) {
                        return result;
                    }
                    body_progress_ += header_line.size() - body_content.size();
                    body_content.clear();
                } else {
                    header_line = body_content.substr(0, pos + 1);
                    body_content.erase(0, pos + 1);
                }
            }

            log_->Debug(header_line);

            if (!header_line.compare("\r\n")) {
                break;
            }

            std::smatch m;
            if (std::regex_match(header_line, m, re_content_type)) {
                // TODO: multipart/mixed support
                fileinfo.file.content_type = m[1];
            } else if (std::regex_match(header_line, m,
                                        re_content_disposition)) {
                fileinfo.name = m[1];
                fileinfo.file.filename = m[2];
            }
            header_line.clear();
        }
        parse_status_ = ParseStatus::multipart_read_file;
        return VoidResult::OK();
    }

    Result<std::string> get_boundary() {
        auto content_type =
            get_header_value_string(req_->headers, CONTENT_TYPE);
        if (!content_type.IsOK()) {
            return content_type;
        }

        auto boundary_pos = content_type.Get().find("boundary=");
        if (boundary_pos == std::string::npos) {
            return VoidResult::ErrorResult<HttpError>("parse multipart error");
        }
        return content_type.Get().substr(boundary_pos + 9);
    }

    VoidResult parse_multipart_formdata_file() {
        VoidResult result;

        static std::string dash = "--";
        static std::string crlf = "\r\n";
        static size_t crlf_size = crlf.size();

        auto boundary_result = get_boundary();
        if (!boundary_result.IsOK()) {
            return result;
        }
        std::string boundary = boundary_result.Get();

        auto content_length_result =
            get_header_value_int(req_->headers, CONTENT_LENGTH);
        if (!content_length_result.IsOK()) {
            return VoidResult::ErrorResult<HttpError>("http format error");
        }
        auto content_length = content_length_result.Get();

        std::string dash_boundary = dash + boundary;
        size_t dash_boundary_size = dash_boundary.size();
        std::string &content = multipart_data_buf_;

        static const size_t MAX_MULTIPART_READ_SIZE = 4 * 1024;
        size_t rest_body_len = 0;
        size_t read_size = 0;
        size_t offset = 0;

        MultipartFileInfo &fileinfo = multipart_file_info_;
        File **file = &fileinfo.file.file;
        bool is_read_finish = false;

        while (body_progress_ != content_length) {
            rest_body_len = content_length - body_progress_;
            if (MAX_MULTIPART_READ_SIZE > rest_body_len) {
                read_size = rest_body_len;
            } else if (MAX_MULTIPART_READ_SIZE < rest_body_len) {
                read_size = MAX_MULTIPART_READ_SIZE;
            }

            offset = content.size();
            if (offset == 0) {
                content.assign(read_size, 0);
            }
            if (read_size < MAX_MULTIPART_READ_SIZE) {
                content.resize(read_size + offset);
                result = read_len(&content[offset], read_size);
                offset = 0;
            } else {
                content.resize(read_size);
                result = read_len(&content[offset], read_size - offset);
            }
            if (!result.IsOK()) {
                content.resize(offset);
                return result;
            }
            body_progress_ += (read_size - offset);

            auto pos = content.find(crlf + dash_boundary);

            if (pos == std::string::npos) {
                is_read_finish = false;
                pos = read_size - dash_boundary_size - crlf_size;
            } else {
                is_read_finish = true;
            }

            if (*file == nullptr) {
                std::string filename =
                    string_format("tmp_%s_%s", fileinfo.name.c_str(),
                                  fileinfo.file.filename.c_str());
                if (pos <
                    MAX_MULTIPART_READ_SIZE - dash_boundary_size - crlf_size) {
                    *file = new MemFile(filename);
                } else {
                    *file = new File(filename);
                }

                if (!*file) {
                    return VoidResult::ErrorResult<OutOfMemory>(
                        "allocate File");
                }

                if (!(*file)->IsOpen()) {
                    result = (*file)->Create();
                    if (!result.IsOK()) {
                        return result;
                    }
                }

                multipart_file_writer_ = FileWriter(**file);
            }

            result = multipart_file_writer_.Write(&content[0], pos);
            if (!result.IsOK()) {
                return result;
            }

            fileinfo.file.length += pos;

            if (is_read_finish) {
                std::string boundary_rear =
                    content.substr(pos + crlf_size + dash_boundary_size, 2);
                if (!boundary_rear.compare("\r\n")) {
                    content.erase(0, pos + crlf_size * 2 + dash_boundary_size);
                    parse_status_ = ParseStatus::multipart_read_header;
                } else if (!boundary_rear.compare("--")) {
                    parse_status_ = ParseStatus::route;
                    content.clear();
                }
                req_->files.emplace(fileinfo.name, fileinfo.file);
                log_->Debug(string_format("filename=%s,filesize=%d",
                                          fileinfo.file.filename.c_str(),
                                          fileinfo.file.length));
                fileinfo.file.file = nullptr;
                fileinfo.file.length = 0;
                result = multipart_file_writer_.Flush();
                if (!result.IsOK()) {
                    return result;
                }
                break;
            } else {
                content.erase(0, pos);
            }
        }

        return VoidResult::OK();
    }

    VoidResult read_content_without_length() { return VoidResult::OK(); }

    VoidResult read_len(char *buf, size_t len) {
        if (buf_.size() != len) {
            buf_.assign(len, 0);
        }
        Result<ssize_t> rsize =
            reader_.Read(&buf_[buf_progress_], len - buf_progress_);
        if (!rsize.IsOK()) {
            if (rsize.IsError<FileAgain>()) {
                buf_progress_ += rsize.Get();
                log_->Debug(string_format("progress: %d", buf_progress_));
                return VoidResult::ErrorResult<HttpAgain>("http read again!");
            }
            return rsize;
        }
        if (rsize.Get() != len - buf_progress_) {
            buf_progress_ += rsize.Get();
            log_->Debug(string_format("progress: %d", buf_progress_));
            if (buf_progress_ != len) {
                return VoidResult::ErrorResult<HttpAgain>("http read again!");
            }
        }
        memcpy(buf, buf_.data(), len);
        buf_progress_ = 0;
        buf_.clear();
        return VoidResult::OK();
    }

    VoidResult read_line(std::string &line) {
        VoidResult result = reader_.ReadLine(buf_);
        if (!result.IsOK()) {
            if (result.IsError<FileAgain>()) {
                log_->Debug(buf_);
                return VoidResult::ErrorResult<HttpAgain>("http read again!");
            };
            return result;
        }

        if (buf_.back() != '\n') {
            log_->Debug(buf_);
            return VoidResult::ErrorResult<HttpAgain>("http read again!");
        }
        line.assign(buf_);
        buf_.clear();
        return VoidResult::OK();
    }

    inline Result<const char *> get_header_value(const Headers &headers,
                                                 const char *key) {
        auto it = headers.find(key);
        if (it != headers.end()) {
            return it->second.c_str();
        }
        return VoidResult::ErrorResult<HttpError>("do not exist header");
    }

    inline Result<std::string> get_header_value_string(const Headers &headers,
                                                       const char *key) {
        auto result = get_header_value(headers, key);
        if (result.IsOK()) {
            return std::string(result.Get());
        }
        return result;
    }

    inline Result<int> get_header_value_int(const Headers &headers,
                                            const char *key) {
        auto result = get_header_value(headers, key);
        if (result.IsOK()) {
            return std::stoi(result.Get());
        }
        return result;
    }

    void route_handle() {
        parse_status_ = ParseStatus::finish;
        res_->status = 200;
        if (handle_file_request()) {
            return;
        }
        if (!dispatch_request()) {
            res_->status = 404;
        }
    }

    bool handle_file_request() {
        if (req_->method != GET) {
            return false;
        }

        const HttpServerOption &option = server_->option;
        std::string file = option.root_dir + req_->path;
        MultipartFile multipartfile;
        if (req_->path == "/") {
            std::vector<std::string> entry_files{"index.html"};
            VoidResult result;
            auto it = entry_files.cbegin();
            for (; it != entry_files.cend(); ++it) {
                if (File::IsExist(file + *it)) {
                    file.append(*it);
                    break;
                }
            }
            if (it == entry_files.end()) {
                return false;
            }
        }

        if (File::IsExist(file)) {
            multipartfile.file = new File(file);
            res_->files.emplace(file, multipartfile);
            return true;
        }
        log_->Debug(req_->path);
        return false;
    }

    bool dispatch_request() {
        HttpHandlers &handlers = server_->method_handlers[req_->method];
        std::smatch m;
        for (const auto &handler : handlers) {
            if (std::regex_match(req_->path, m, handler.pattern)) {
                handler.func(*req_, *res_);
                return true;
            }
        }
        return false;
    }

    void close_socket() { delete connect_socket_; }

    HttpServerImpl *server_;
    Socket *connect_socket_;
    HttpRequest *req_;
    HttpResponse *res_;

    FileReader reader_;
    Log *log_;

    enum class ParseStatus {
        request_line,
        request_headers,
        post_query,
        multipart_read_header,
        multipart_read_file,
        route,
        finish
    };

    ParseStatus parse_status_;
    std::string buf_;
    ssize_t buf_progress_;
    ssize_t body_progress_;

    typedef struct MultipartFileInfo {
        std::string name;
        MultipartFile file;
    } MultipartFileInfo;
    MultipartFileInfo multipart_file_info_;
    std::string multipart_data_buf_;
    FileWriter multipart_file_writer_;

}; // namespace MyServer

void HttpServerResponseListener::Callback(EventLoop *loop) {
    auto result = server_socket_->Accept();
    if (!result.IsOK()) {
        loop->LOG()->Debug(result.str());
        return;
    }
    Socket *connectSocket = result.Get();
    result = connectSocket->setNonBlocking();
    if (!result.IsOK()) {
        loop->LOG()->Debug(result.str());
        return;
    }
    Listener *listener = new HttpRequestReadListener(connectSocket, server_);
    result = loop->AddListener(connectSocket->GetFd(), IOEvent::READ, listener);
    if (!result.IsOK()) {
        loop->LOG()->Debug("fd " + std::to_string(connectSocket->GetFd()) +
                           " add listener failure!" + result.str());
        return;
    }
}

} // namespace

Result<HttpServer *> HttpServer::NewHttpServer(const HttpServerOption &option) {
    HttpServerImpl *server = new HttpServerImpl(option);
    if (server == nullptr) {
        return VoidResult::ErrorResult<OutOfMemory>();
    }
    VoidResult result = server->ApplyOption();
    if (!result.IsOK()) {
        return result;
    }
    return server;
}

std::string *HttpResponse::GetResponseHeader() {
    std::string *response = new std::string;
    // response line
    response->append(string_format("%s %s\r\n", version.c_str(),
                                   std::to_string(status).c_str()));

    // response header
    for (auto header : headers) {
        response->append(string_format("%s: %s\r\n", header.first.c_str(),
                                       header.second.c_str()));
    }
    response->append("\r\n");
    return response;
}

} // namespace MyServer
