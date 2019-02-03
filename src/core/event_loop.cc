#include "event_loop.h"

#include <cassert>
#include <map>

#include "common/singleton.h"

namespace MyServer {

namespace {
class EventLoopImpl : public EventLoop {
  public:
    EventLoopImpl(const LogOption &option) : logger_(new Log(option)) {}
    ~EventLoopImpl() override = default;
    VoidResult Init() {
        auto result = IOPoll::newIOPoll(IOPollBackend::EPOLL);
        if (!result.IsOK()) {
            return result;
        }

        iopoll_ = result.Get();
        return VoidResult::OK();
    }

    VoidResult Run() override {
        VoidResult result;
        for (;;) {
            // TODO: computer timeout
            std::vector<PollEvent> pollEvents;
            result = iopoll_->Poll(pollEvents, 100);
            if (!result.IsOK()) {

                break;
            }
            FileDesc fd;
            for (auto event : pollEvents) {
                fd = event.data.fd;
                auto flag = ioEvents_[fd].event;
                if (flag & event.event & IOEvent::READ) {
                    // assert(ioEvents_[fd].read == nullptr);
                    ioEvents_[fd].read->Callback(this);
                } else if (flag & event.event & IOEvent::WRITE) {
                    // assert(ioEvents_[fd].write == nullptr);
                    ioEvents_[fd].write->Callback(this);
                }
            }
        }
        return result;
    }
    void Exit() override {}

    VoidResult AddListener(FileDesc fd, IOEvent event,
                           Listener *listener) override {
        if (listener == nullptr) {
            return VoidResult::ErrorResult<NullPointer>();
        }
        FdWatcher watcher;
        watcher.fd = fd;
        watcher.event = event;
        watcher.data.fd = fd;

        VoidResult result;
        IOEventFlag flag = ioEvents_[fd].event;
        if (flag == 0) {
            flag = event;
            result = iopoll_->Add(watcher);
        } else {
            flag |= event;
            watcher.event = flag;
            result = iopoll_->Modify(watcher);
        }

        if (!result.IsOK()) {
            return result;
        }

        ioEvents_[fd].event = flag;

        if (event == IOEvent::READ) {
            ioEvents_[fd].read = listener;
        } else if (event == IOEvent::WRITE) {
            ioEvents_[fd].write = listener;
        }

        return VoidResult::OK();
    };

    VoidResult RemoveListener(FileDesc fd, IOEvent event) override {
        if (ioEvents_[fd].event == 0) {
            return VoidResult::ErrorResult<EventLoopError>(
                "The listener is not exist!");
        }
        FdWatcher watcher;
        watcher.fd = fd;
        watcher.data.fd = fd;

        VoidResult result;
        IOEventFlag flag = ioEvents_[fd].event;
        if (flag != event) {
            flag &= ~event;
            watcher.event = flag;
            result = iopoll_->Modify(watcher);
        } else {
            flag = 0;
            watcher.event = flag;
            result = iopoll_->Delete(watcher);
        }
        if (!result.IsOK()) {
            return result;
        }
        ioEvents_[fd].event = flag;
        if (event == IOEvent::READ) {
            ioEvents_[fd].read = nullptr;
        } else if (event == IOEvent::WRITE) {
            ioEvents_[fd].write = nullptr;
        }        
        return VoidResult::OK();
    }

    Log *LOG() override { return logger_; }

  private:
    IOPoll *iopoll_;
    Log *logger_;

    struct IOEventListener {
        IOEventFlag event;
        Listener *write;
        Listener *read;
    };
    std::map<FileDesc, IOEventListener> ioEvents_;
};

} // namespace

Result<EventLoop *> EventLoop::NewEventLoop(const LogOption &logOption) {
    EventLoopImpl *loop = new EventLoopImpl(logOption);
    if (loop == nullptr) {
        return VoidResult::ErrorResult<OutOfMemory>(
            "allocate EventLoop object");
    }
    auto result = loop->Init();
    if (!result.IsOK()) {
        delete loop;
        return result;
    }
    return loop;
}

} // namespace MyServer
