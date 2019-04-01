#include "event_loop.h"

#include <cassert>
#include <map>
#include <sys/time.h>

#include "common/singleton.h"

namespace MyServer {

namespace {
class EventLoopImpl : public EventLoop {
  public:
    EventLoopImpl(const LogOption &option) : logger_(new Log(option)), timeridcnt_(0) {}
    ~EventLoopImpl() override {
        delete iopoll_;
        delete logger_;
    };
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
            result = iopoll_->Poll(pollEvents, 200);
            if (!result.IsOK()) {
                break;
            }
            FileDesc fd;
            for (auto event : pollEvents) {
                fd = event.data.fd;
                IOEventListener &ioevent = ioEvents_[fd];
                auto flag = ioEvents_[fd].event;
                if (flag & event.event & IOEvent::READ) {
                    ioevent.read->Callback(this);
                }

                if (flag & event.event & IOEvent::WRITE) {
                    ioevent.write->Callback(this);
                }

                // if (event.event & IOEvent::ERR) {
                //     Listener *listener;
                //     if ((listener = ioevent.read) != nullptr) {
                //         auto result = RemoveListener(fd, IOEvent::READ);
                //         delete listener;
                //     }
                //     if ((listener = ioevent.write) != nullptr) {
                //         RemoveListener(fd, IOEvent::WRITE);
                //         delete listener;
                //     }
                // }
            }
            Result<Time> now_result = getTime();
            if (!now_result.IsOK()) {
                result = now_result;
                break;
            }
            Time now = now_result.Get();
            auto it = timers_.begin();
            for (; it != timers_.end(); ++it) {
                if (it->first < now) {
                    it->second.timer->Callback(this);
                } else {
                    break;
                }
            }
	    timers_.erase(timers_.begin(), it);
        }
        if (!result.IsOK()) {
            logger_->ERROR(result.str());
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
        IOEventListener &ioevent = ioEvents_[fd];
        IOEventFlag &flag = ioevent.event;
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

        if (event == IOEvent::READ) {
            ioevent.read = listener;
        } else if (event == IOEvent::WRITE) {
            ioevent.write = listener;
        }

        return VoidResult::OK();
    };

    VoidResult RemoveListener(FileDesc fd, IOEvent event) override {
        auto it = ioEvents_.find(fd);
        if (it == ioEvents_.end()) {
            return VoidResult::ErrorResult<EventLoopError>(
                "The listener is not exist!");
        }

        FdWatcher watcher;
        watcher.fd = fd;
        watcher.data.fd = fd;

        VoidResult result;
        IOEventListener &ioevent = it->second;
        IOEventFlag &flag = ioevent.event;
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

        if (event == IOEvent::READ) {
            ioevent.read = nullptr;
        } else if (event == IOEvent::WRITE) {
            ioevent.write = nullptr;
        }

        if (ioevent.read == nullptr && ioevent.write == nullptr) {
            ioEvents_.erase(fd);
        }

        return VoidResult::OK();
    }
    Result<TimerId> AddTimer(Time after, Listener *timer) override {
        auto result = getTime();
        if (!result.IsOK()) {
            return result;
        }

        TimerListener listener;
        listener.timer = timer;	
        listener.id = timeridcnt_++;
        listener.after += after + result.Get();
	
        timers_.emplace(listener.after, listener);
        return listener.id;
    }

    Result<Listener *> RemoveTimer(TimerId id) override {
        auto it = timers_.begin();
        Listener *timer = nullptr;
        for (; it != timers_.end(); ++it) {
            if (it->second.id == id) {
                timer = it->second.timer;
                break;
            }
        }

        if (it == timers_.end()) {
            return Result<Listener *>(nullptr,
                                   VoidResult::ErrorResult<EventLoopError>(
                                       "The Timer is not exist"));
        }

        timers_.erase(it);
        return timer;
    }

    Log *LOG() override { return logger_; }

  private:
    Result<Time> getTime() {
        bool TIME_PRECISION_NANO = true;
        int ret = 0;
        Time time = 0;
        if (TIME_PRECISION_NANO) {
            struct timespec ts;
            ret = clock_gettime(CLOCK_MONOTONIC, &ts);
            time = ts.tv_sec + ts.tv_nsec * 1e-9;
        } else {
            struct timeval tv;
            ret = gettimeofday(&tv, NULL);
            time = tv.tv_sec + tv.tv_usec * 1e-6;
        }
        if (ret == -1) {
            return VoidResult::ErrorResult<SysError>("", errno);
        }

        return time;
    }

    IOPoll *iopoll_;
    Log *logger_;

    struct IOEventListener {
        IOEventFlag event;
        Listener *write = nullptr;
        Listener *read = nullptr;
    };
    std::map<FileDesc, IOEventListener> ioEvents_;

    struct TimerListener {
        Listener *timer = nullptr;
        TimerId id;
	Time after;
    };
    std::multimap<Time, TimerListener> timers_;
    long long timeridcnt_;
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
