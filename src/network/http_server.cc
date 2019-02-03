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
          is_request_line_read_(false), is_request_header_read_(false),
          is_request_body_read_(false), body_progress(0), connect_close_(true) {
    }

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

        result = parse_request_line();
        if (!result.IsOK()) {
            return result;
        }

        result = parse_headers();
        if (!result.IsOK()) {
            return result;
        }

        result = parse_body();
        if (!result.IsOK()) {
            return result;
        }

        // INFO: DEBUG
        log_->Debug("param:");
        for (const auto &param : req_->params) {
            log_->Debug(param.first + "=" + param.second);
        }
        log_->Debug("");

        if (route_handle()) {
            res_->status = 200;
        } else {
            res_->status = 404;
        }
        return VoidResult::OK();
    }

    VoidResult parse_request_line() {
        if (is_request_line_read_) {
            return VoidResult::OK();
        }
        std::string request_line;
        VoidResult result = read_line(request_line);
        if (!result.IsOK()) {
            return result;
        }

        is_request_line_read_ = true;
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
            return VoidResult::OK();
        }
        return VoidResult::ErrorResult<HttpError>("parse request line fail!");
    }

    inline void parse_query_text(const std::string &s, Params &params) {
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
        if (is_request_header_read_) {
            return VoidResult::OK();
        }
        static std::regex re(R"((.+?):\s*(.+?)\s*\r\n)");
        std::string header_line;
        VoidResult result;

        for (;;) {
            result = read_line(header_line);
            if (!result.IsOK()) {
                return result;
            }

            if (!header_line.compare("\r\n")) {
                is_request_header_read_ = true;
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
        return VoidResult::OK();
    }

    VoidResult parse_body() {
        // parse Body
        VoidResult result;
        if (req_->method == POST || req_->method == PUT) {
            result = read_body();
            if (!result.IsOK()) {
                return result;
            }
            auto content_type =
                get_header_value_string(req_->headers, CONTENT_TYPE);
            if (!content_type.IsOK()) {
                return content_type;
            }
            if (!content_type.Get().find("application/x-www-form-urlencoded")) {
                parse_query_text(req_->body, req_->params);
            } else if (!content_type.Get().find("multipart/form-data")) {
                // TODO: Deferred file transmission
                result = parse_multipart(content_type.Get());
                if (!result.IsOK()) {
                    return result;
                }
            }
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
        if (is_request_body_read_) {
            return VoidResult::OK();
        }

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
        is_request_body_read_ = true;
        log_->Debug("read body finish");
        return VoidResult::OK();
    }

    VoidResult read_content_without_length() { return VoidResult::OK(); }

    VoidResult read_content_with_length(size_t len) {
        if (req_->body.size() != len) {
            req_->body.assign(len, 0);
        }
        Result<ssize_t> rsize =
            reader_.Read(&((req_->body)[body_progress]), len - body_progress);
        if (!rsize.IsOK()) {
            if (rsize.IsError<FileAgain>()) {
                body_progress += rsize.Get();
                log_->Debug(string_format("progress: %d", body_progress));
                return VoidResult::ErrorResult<HttpReadAgain>(
                    "http read again!");
            }
            return rsize;
        } else {
            body_progress += rsize.Get();
            log_->Debug(string_format("progress: %d", body_progress));
            if (body_progress != len) {
                return VoidResult::ErrorResult<HttpReadAgain>(
                    "http read again!");
            }
        }
        return VoidResult::OK();
    }

    VoidResult read_line(std::string &line) {
        VoidResult result = reader_.ReadLine(buf_);
        if (!result.IsOK()) {
            if (result.IsError<FileAgain>()) {
                return VoidResult::ErrorResult<HttpReadAgain>(
                    "http read again!");
            };
            return result;
        } else {
            if (buf_.back() != '\n') {
                return VoidResult::ErrorResult<HttpReadAgain>(
                    "http read again!");
            }
        }

        line.assign(buf_);
        log_->Debug(line);
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

    bool is_request_line_read_;
    bool is_request_header_read_;
    bool is_request_body_read_;
    std::string buf_;
    ssize_t body_progress;

    bool connect_close_;
};

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
