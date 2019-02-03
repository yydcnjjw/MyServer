#ifndef SERVER_H
#define SERVER_H

#include "core/event_loop.h"

namespace MyServer {
class Server {
  public:
    Server() = default;
    virtual ~Server() = default;

    virtual VoidResult Start() = 0;
    virtual VoidResult Stop() = 0;
    virtual VoidResult Restart() = 0;
    virtual VoidResult addToEventLoop(EventLoop *) = 0;
};

} // namespace MyServer

#endif /* SERVER_H */
