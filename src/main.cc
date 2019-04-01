#include <iostream>

#include <signal.h>

#include "network/http_server.h"

using namespace Utils;
using namespace MyServer;
using namespace std;

void handle(int signum) {
    exit(0);
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    // ::signal(SIGINT, handle);
    HttpServerOption option = {
        .root_dir = "web", .host = "localhost", .port = "8080"};
    
    auto result = HttpServer::NewHttpServer(option);
    if (!result.IsOK()) {
        cout << result.str() << endl;
        return -1;
    }
    
    HttpServer *server = result.Get();
    server->Get("/", [](const HttpRequest &req, HttpResponse &res) {
        cout << "Hello World!" << endl;
    });
    
    server->Post("/", [](const HttpRequest &req, HttpResponse &res) {
        res.body = "Hello World!";
    });

    server->Start();
    return 0;
}
