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
typedef std::multimap<std::string, std::string> Querys;

class Url {
  public:
    std::string host;
    std::string path;
    Querys querys;
    Querys AddParam(const std::string &key, const std::string &value);
    Querys RemoveParam(const std::string &key);
};

typedef struct MultipartFile {
    std::string filename;
    std::string content_type;
    File *file = nullptr;
    size_t length = 0;
} MultipartFile;
typedef std::multimap<std::string, MultipartFile> MultipartFiles;

class HttpMessage {
  public:
    std::string version;
    Headers headers;
    MultipartFiles files;
};

class HttpResponse : public HttpMessage {
  public:
    int status;
    std::string body;
};

class HttpRequest : public HttpMessage {
  public:
    std::string method;
    std::string target;
    std::string path;
    Params params;
};

typedef std::function<void(const HttpRequest &, HttpResponse &)> HttpHandleFunc;

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
