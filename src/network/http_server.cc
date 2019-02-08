
#include "http_server.h"

#include <unistd.h>

#include <regex>

#include "core/event_listener.h"
#include "core/event_loop.h"
#include "utils/file_util.h"
#include "utils/log.h"
#include "utils/string_util.h"

namespace MyServer {
namespace {

const char *HTTP_V1_0 = "HTTP/1.0";
const char *HTTP_V1_1 = "HTTP/1.1";
enum HTTP_STATUS { OK = 0, CONNECT = 1 };

const char *GET = "GET";
const char *POST = "POST";
const char *PUT = "PUT";
// const char *CONNECT = "connect";

const char *CONTENT_LENGTH = "Content-Length";
const char *CONTENT_TYPE = "Content-Type";

typedef std::vector<HttpHandler> HttpHandlers;
class HttpReadAgain : public HttpError {
  public:
    HttpReadAgain() {}
};
class HttpServerImpl;

class HttpServerResponseListener : public Listener {
  public:
    HttpServerResponseListener(Socket *serverSocket, HttpServerImpl *server)
        : server_socket_(serverSocket), server_(server) {}

    ~HttpServerResponseListener() override = default;
    void Callback(EventLoop *loop) override;

  private:
    Socket *server_socket_;
    HttpServerImpl *server_;
};

class HttpServerImpl : public HttpServer {
  public:
    // TODO: current dir use absolute
    HttpServerImpl()
        : root_dir("."), method_handlers({{GET, {}}, {POST, {}}}),
          server_socket_(nullptr), loop_(nullptr), server_iolistener_(nullptr),
          isStart_(false) {}
    ~HttpServerImpl() override = default;

    HttpServer *Get(const std::string &re, HttpHandleFunc func) override {
        method_handlers[GET].push_back({std::regex(re), func});
        return this;
    }
    HttpServer *Post(const std::string &re, HttpHandleFunc func) override {
        method_handlers[POST].push_back({std::regex(re), func});
        return this;
    }

    VoidResult setRootDir(const std::string &path) override {
        // TODO: is valid root dir
        root_dir = path;
        return VoidResult::OK();
    }

    VoidResult Listen(const std::string &host,
                      const std::string &port) override {

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
        if (server_socket_ == nullptr) {
            return VoidResult::ErrorResult<HttpError>("Not bind host and port");
        }
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

  public:
    std::string root_dir;
    std::map<std::string, HttpHandlers> method_handlers;

  private:
    Socket *server_socket_;
    EventLoop *loop_;

    std::vector<HttpHandler> http_handles_;

    HttpServerResponseListener *server_iolistener_;
    bool isStart_;
};

class HttpRequestWriteListener : public Listener {
  public:
    HttpRequestWriteListener(Socket *connectSocket, HttpServerImpl *server,
                             HttpRequest *req, HttpResponse *res)
        : server_(server), connect_socket_(connectSocket), req_(req), res_(res),
          file_writer_(FileWriter(connectSocket->GetFd())) {}

    ~HttpRequestWriteListener() override {
        delete connect_socket_;
        delete req_;
        delete res_;
    };

    void Callback(EventLoop *loop) override {
        if (log_ == nullptr) {
            log_ = loop->LOG();
        }
        std::string data = "HTTP/1.1 200 OK\nContent-Length: 13\nContent-Type: "
                           "text/html\n\nHello world!\n";
        auto result = file_writer_.Append(data);
        if (!result.IsOK()) {
            log_->Debug(result.str());
        }
        result = file_writer_.Flush();
        if (!result.IsOK()) {
            log_->Debug(result.str());
        }
        loop->RemoveListener(connect_socket_->GetFd(), IOEvent::WRITE);
        delete this;
    }

  private:
    HttpServerImpl *server_;
    Socket *connect_socket_;
    HttpRequest *req_;
    HttpResponse *res_;

    FileWriter file_writer_;
    Log *log_;
};

class HttpRequestReadListener : public Listener {
  public:
    HttpRequestReadListener(Socket *connectSocket, HttpServerImpl *server)
        : server_(server), connect_socket_(connectSocket),
          req_(new HttpRequest), res_(new HttpResponse),
          reader_(FileReader(connect_socket_->GetFd())), log_(nullptr),
          parse_status_(ParseStatus::request_line), buf_progress_(0),
          body_progress_(0), connect_close_(true) {}

    ~HttpRequestReadListener() override{};

    void Callback(EventLoop *loop) override {
        if (log_ == nullptr) {
            log_ = loop->LOG();
        }
        FileDesc fd = connect_socket_->GetFd();
        VoidResult result = handle_request(loop);

        if (!result.IsOK()) {
            if (result.IsError<HttpReadAgain>()) {
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
                if (route_handle()) {
                    res_->status = 200;
                } else {
                    res_->status = 404;
                }
                parse_status_ = ParseStatus::finish;
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
        VoidResult result = read_body();
        if (!result.IsOK()) {
            return result;
        }
        parse_query_text(req_->body, req_->params);
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

        auto content_length =
            get_header_value_int(req_->headers, CONTENT_LENGTH);
        if (!content_length.IsOK()) {
            return VoidResult::ErrorResult<HttpError>("http format error");
        }

        size_t rest_body_len = content_length.Get() - body_progress_;
        size_t read_size = 0;
        static const size_t MAX_MULTIPART_READ_SIZE = 4 * 1024;
        if (MAX_MULTIPART_READ_SIZE > rest_body_len) {
            read_size = rest_body_len;
        } else if (MAX_MULTIPART_READ_SIZE < rest_body_len) {
            read_size = MAX_MULTIPART_READ_SIZE;
        }

        std::string dash_boundary = dash + boundary;
        size_t dash_boundary_size = dash_boundary.size();
        std::string &content = multipart_data_buf_;
        size_t offset = content.size();
        if (offset == 0) {
            content.assign(read_size, 0);
        }

        if (body_progress_ != content_length.Get()) {
            if (read_size < 4 * 1024) {
                content.resize(read_size + offset);
                result = read_len(&content[offset], read_size);
                offset = 0;
            } else {
                content.resize(read_size);
                result = read_len(&content[offset], read_size - offset);
            }
            if (!result.IsOK()) {
                return result;
            }
            body_progress_ += (read_size - offset);
        }

        auto pos = content.find(crlf + dash_boundary);

        bool is_read_finish = false;
        if (pos == std::string::npos) {
            pos = read_size - dash_boundary_size - crlf_size;
        } else {
            is_read_finish = true;
        }

        MultipartFileInfo &fileinfo = multipart_file_info_;
        File **file = &fileinfo.file.file;
        std::string filename = string_format("tmp_%s_%s", fileinfo.name.c_str(),
                                             fileinfo.file.filename.c_str());
        if (*file == nullptr) {

            if (pos <
                MAX_MULTIPART_READ_SIZE - dash_boundary_size - crlf_size) {
                *file = new MemFile(filename);
            } else {
                *file = new File(filename);
            }

            if (!file) {
                return VoidResult::ErrorResult<OutOfMemory>("allocate File");
            }

            if (!(*file)->IsOpen()) {
                result = (*file)->Create();
                if (!result.IsOK()) {
                    return result;
                }
            }

            multipart_file_writer_ = FileWriter((*file)->GetFileDesc());
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

        } else {
            content.erase(0, pos);
        }

        return VoidResult::OK();
    }

    // Code modified from function parse_multipart_fromdata
    // obtained from https://github.com/yhirose/cpp-httplib
    VoidResult parse_multipart(const std::string &content_type) {
        // parse boundary
        auto boundary_pos = content_type.find("boundary=");
        if (boundary_pos == std::string::npos) {
            return VoidResult::ErrorResult<HttpError>("parse multipart error");
        }

        static std::string crlf = "\r\n";
        static std::string dash = "--";
        // parse multipart file data
        static std::regex re_content_type("Content-Type: (.*?)",
                                          std::regex_constants::icase);
        static std::regex re_content_disposition(
            "Content-Disposition: form-data; name=\"(.*?)\"(?:; "
            "filename=\"(.*?)\")?",
            std::regex_constants::icase);

        std::string boundary = content_type.substr(boundary_pos + 9);
        std::string dash_boundary = dash + boundary;

        const std::string &body = req_->body;
        size_t body_size = body.size();

        auto pos = body.find(dash_boundary);
        if (pos != 0) {
            log_->Debug("parse error 1");
            return VoidResult::ErrorResult<HttpError>("parse multipart error");
        }

        pos += dash_boundary.size();

        auto next_pos = body.find(crlf, pos);
        if (next_pos == std::string::npos) {
            log_->Debug("parse error 2");
            return VoidResult::ErrorResult<HttpError>("parse multipart error");
        }

        pos = next_pos + crlf.size();

        while (pos < body.size()) {
            next_pos = body.find(crlf, pos);
            if (next_pos == std::string::npos) {
                return VoidResult::ErrorResult<HttpError>(
                    "parse multipart error");
            }

            std::string name;
            MultipartFile file;

            auto header = body.substr(pos, (next_pos - pos));

            while (pos != next_pos) {
                log_->Debug(header);
                std::smatch m;
                if (std::regex_match(header, m, re_content_type)) {
                    // TODO: multipart/mixed support
                    file.content_type = m[1];
                } else if (std::regex_match(header, m,
                                            re_content_disposition)) {
                    name = m[1];
                    file.filename = m[2];
                }

                pos = next_pos + crlf.size();

                next_pos = body.find(crlf, pos);
                if (next_pos == std::string::npos) {
                    return VoidResult::ErrorResult<HttpError>(
                        "parse multipart error");
                }

                header = body.substr(pos, (next_pos - pos));
            }

            pos = next_pos + crlf.size();

            next_pos = body.find(crlf + dash_boundary, pos);

            if (next_pos == std::string::npos) {
                return VoidResult::ErrorResult<HttpError>(
                    "parse multipart error");
            }

            file.offset = pos;
            file.length = next_pos - pos;

            pos = next_pos + crlf.size() + dash_boundary.size();

            next_pos = body.find(crlf, pos);
            if (next_pos == std::string::npos) {
                return VoidResult::ErrorResult<HttpError>(
                    "parse multipart error");
            }

            req_->files.emplace(name, file);
            log_->Debug(string_format(
                "id = %s, fileanme = %s, file length = %d", name.c_str(),
                file.filename.c_str(), file.length));

            pos = next_pos + crlf.size();
        }
        return VoidResult::OK();
    }

    VoidResult read_body() {
        auto content_length =
            get_header_value_int(req_->headers, CONTENT_LENGTH);

        VoidResult result;
        if (content_length.IsOK() && content_length.Get() > 0) {
            result = read_content_with_length(content_length.Get());
        } else {
            // TODO: chunked
            result = read_content_without_length();
        }
        log_->Debug(result.str());

        if (!result.IsOK()) {
            return result;
        }
        return VoidResult::OK();
    }

    VoidResult read_content_without_length() { return VoidResult::OK(); }

    VoidResult read_content_with_length(size_t len) {
        if (req_->body.size() != len) {
            req_->body.assign(len, 0);
        }
        Result<ssize_t> rsize =
            reader_.Read(&((req_->body)[body_progress_]), len - body_progress_);
        if (!rsize.IsOK()) {
            if (rsize.IsError<FileAgain>()) {
                body_progress_ += rsize.Get();
                log_->Debug(string_format("progress: %d", body_progress_));
                return VoidResult::ErrorResult<HttpReadAgain>(
                    "http read again!");
            }
            return rsize;
        } else {
            body_progress_ += rsize.Get();
            log_->Debug(string_format("progress: %d", body_progress_));
            if (body_progress_ != len) {
                return VoidResult::ErrorResult<HttpReadAgain>(
                    "http read again!");
            }
        }
        return VoidResult::OK();
    }

    VoidResult read_len(char *buf, size_t len) {
        Result<ssize_t> rsize = reader_.Read(buf, len - buf_progress_);
        if (!rsize.IsOK()) {
            if (rsize.IsError<FileAgain>()) {
                buf_progress_ += rsize.Get();
                buf_.append(buf);
                log_->Debug(string_format("progress: %d", buf_progress_));
                return VoidResult::ErrorResult<HttpReadAgain>(
                    "http read again!");
            }
            return rsize;
        }
        if (rsize.Get() != len) {
            if (buf_.size() != len) {
                buf_.assign(len, 0);
            }
            buf_progress_ += rsize.Get();
            log_->Debug(string_format("progress: %d", buf_progress_));
            if (buf_progress_ != len) {
                buf_.append(buf);
                return VoidResult::ErrorResult<HttpReadAgain>(
                    "http read again!");
            }
            memcpy(buf, buf_.data(), len);
            buf_.clear();
        }
        return VoidResult::OK();
    }

    VoidResult read_line(std::string &line) {
        VoidResult result = reader_.ReadLine(line);
        if (!result.IsOK()) {
            if (result.IsError<FileAgain>()) {
                buf_.append(line);
                log_->Debug(buf_);
                return VoidResult::ErrorResult<HttpReadAgain>(
                    "http read again!");
            };
            return result;
        }

        if (line.back() != '\n') {
            buf_.append(line);
            log_->Debug(buf_);
            return VoidResult::ErrorResult<HttpReadAgain>("http read again!");
        }
        if (!buf_.empty()) {
            line.assign(buf_);
        }
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

    bool route_handle() {
        if (handle_file_request()) {
            return true;
        }
        return dispatch_request();
    }

    bool handle_file_request() {
        if (req_->method != GET) {
            return false;
        }

        return true;
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
    bool connect_close_;
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
Result<HttpServer *> HttpServer::NewHttpServer() {

    HttpServer *server = new HttpServerImpl;
    if (server == nullptr) {
        return VoidResult::ErrorResult<OutOfMemory>();
    }
    return server;
}

} // namespace MyServer
