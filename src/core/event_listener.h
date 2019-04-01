#ifndef EVENT_LISTENER_H
#define EVENT_LISTENER_H

#include <functional>

namespace MyServer {
class EventLoop;
class Listener;
// typedef std::function<void(EventLoop *, Listener *, void *data)>
//     ListenerCallBack;

class Listener {
  public:
    virtual ~Listener() = default;
    virtual void Callback(EventLoop *) = 0;
};

typedef double Time;
typedef uint TimerId;

// class EventLoopCycleListener : public Listener {
//   public:
//     EventLoopCycleListener() = default;
//     virtual ~EventLoopCycleListener() = default;

//     virtual Status onInit(EventLoop *) = 0;
//     virtual Status onExit(EventLoop *) = 0;
//     virtual Status onRun(EventLoop *) = 0;
// };

} // namespace MyServer

#endif /* EVENT_LISTENER_H */
