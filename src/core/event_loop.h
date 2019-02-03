#ifndef EVENT_LOOP_H
#define EVENT_LOOP_H

#include <functional>
#include <list>
#include <vector>

#include "event_listener.h"
#include "utils/error_util.h"
#include "utils/file_util.h"
#include "utils/log.h"

namespace MyServer {
using namespace Utils;

enum IOEvent { READ = 0x1, WRITE = 0x2 };

class EventLoop {
  public:
    EventLoop() = default;
    virtual ~EventLoop() = default;

    static Result<EventLoop *> NewEventLoop(const LogOption &logOption);

    virtual VoidResult Run() = 0;
    virtual void Exit() = 0;

    virtual VoidResult AddListener(FileDesc, IOEvent, Listener *) = 0;
    virtual VoidResult RemoveListener(FileDesc, IOEvent) = 0;

    virtual Log *LOG() = 0;
};

class EventLoopError : public Error {
  public:
    EventLoopError() : Error("Event Loop Error") {}
};

}; // namespace MyServer

#endif /* EVENT_LOOP_H */
