#include <iostream>

#include "network/http_server.h"

using namespace Utils;
using namespace MyServer;
using namespace std;

int main(int argc, char *argv[]) {
    auto result = HttpServer::NewHttpServer();
    if (!result.IsOK()) {
        cout << result.str() << endl;
        return -1;
    }
    HttpServer *server = result.Get();
    server->Get("/", [](const HttpRequest &req, HttpResponse &res) {
        cout << "Hello World!" << endl;
    });

    server->Listen("localhost", "8080");
    server->Start();
    return 0;
}
