#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <functional>
#include <map>
#include <regex>
#include <string>

#include "server.h"

namespace MyServer {
typedef std::multimap<std::string, std::string> Headers;
typedef std::multimap<std::string, std::string> Params;

typedef struct MultipartFile {
    std::string filename;
    std::string content_type;
    size_t offset = 0;
    size_t length = 0;
} MultipartFile;
typedef std::multimap<std::string, MultipartFile> MultipartFiles;

class HttpResponse {
  public:
    std::string version;
    int status;
    Headers headers;
    std::string body;
};

class HttpRequest {
  public:
    std::string version;
    std::string method;
    std::string target;
    std::string path;
    Headers headers;
    std::string body;
    Params params;
    MultipartFiles files;
};

typedef std::function<void(const HttpRequest &, HttpResponse &)>
    HttpHandleFunc;

struct HttpHandler {
    std::regex pattern;
    HttpHandleFunc func;
};

class HttpServer : public Server {
  public:
    HttpServer() = default;
    virtual ~HttpServer() override = default;

    static Result<HttpServer *> NewHttpServer();

    virtual HttpServer *Get(const std::string &, HttpHandleFunc) = 0;
    virtual HttpServer *Post(const std::string &, HttpHandleFunc) = 0;

    virtual VoidResult setRootDir(const std::string &path) = 0;
    virtual VoidResult Listen(const std::string &host,
                              const std::string &port) = 0;

    virtual VoidResult Start() override = 0;
    virtual VoidResult Stop() override = 0;
    virtual VoidResult Restart() override = 0;
    virtual VoidResult addToEventLoop(EventLoop *) override = 0;
};

class HttpError : public Error {
  public:
    HttpError() : Error("Http Error") {}
};

} // namespace MyServer

#endif /* HTTP_SERVER_H */
