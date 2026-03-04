#include "ThreadManager.h"
#include "../core/Exceptions.h"
#include "../core/Logger.h"
#include "RegisterManager.h"
#include "_scriptapi_debug.h"
#include "bridgemain.h"
#include "_plugins.h"
#include <algorithm>
#include <sstream>
#include <Windows.h>

namespace MCP {

ThreadManager& ThreadManager::Instance() {
    static ThreadManager instance;
    return instance;
}

std::vector<ThreadInfo> ThreadManager::GetThreadList() {
    std::vector<ThreadInfo> threads;

    if (!DbgIsDebugging()) {
        throw DebuggerNotRunningException("Debugger is not debugging");
    }

    THREADLIST threadList;
    memset(&threadList, 0, sizeof(threadList));

    try {
        DbgGetThreadList(&threadList);
        auto cleanupThreadList = [&threadList]() {
            if (threadList.list) {
                BridgeFree(threadList.list);
                threadList.list = nullptr;
            }
        };

        if (threadList.count == 0 || threadList.list == nullptr) {
            LOG_ERROR("No threads found");
            cleanupThreadList();
            return threads;
        }

        uint32_t currentTID = GetCurrentThreadId();

        for (int i = 0; i < threadList.count; i++) {
            ThreadInfo info;
            info.id = static_cast<uint32_t>(threadList.list[i].BasicInfo.ThreadId);
            info.handle = reinterpret_cast<uint64_t>(threadList.list[i].BasicInfo.Handle);
            info.entry = threadList.list[i].BasicInfo.ThreadStartAddress;
            info.teb = threadList.list[i].BasicInfo.ThreadLocalBase;
            info.isCurrent = (info.id == currentTID);
            info.isSuspended = (threadList.list[i].SuspendCount > 0);
            info.priority = threadList.list[i].Priority;
            info.name = GetThreadName(info.id);
            info.rip = threadList.list[i].ThreadCip;

            HANDLE hThread = threadList.list[i].BasicInfo.Handle;
            if (hThread != nullptr) {
                CONTEXT ctx;
                memset(&ctx, 0, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_FULL;

                if (GetThreadContext(hThread, &ctx)) {
#ifdef XDBG_ARCH_X64
                    info.rsp = ctx.Rsp;
                    info.rbp = ctx.Rbp;
                    if (info.rip == 0 && ctx.Rip != 0) {
                        info.rip = ctx.Rip;
                    }
#else
                    info.rsp = ctx.Esp;
                    info.rbp = ctx.Ebp;
                    if (info.rip == 0 && ctx.Eip != 0) {
                        info.rip = ctx.Eip;
                    }
#endif
                    LOG_TRACE("Successfully retrieved context for thread {}: IP=0x{:X}, SP=0x{:X}, BP=0x{:X}",
                              info.id, info.rip, info.rsp, info.rbp);
                } else {
                    info.rsp = 0;
                    info.rbp = 0;
                    DWORD error = GetLastError();
                    LOG_TRACE("GetThreadContext failed for thread {}, error code: {}. Using ThreadCip only.",
                              info.id, error);
                }
            } else {
                info.rsp = 0;
                info.rbp = 0;
                LOG_TRACE("Invalid handle for thread {}, cannot retrieve full context", info.id);
            }

            threads.push_back(info);
        }

        cleanupThreadList();
        LOG_DEBUG("Retrieved {} threads", threads.size());

    } catch (const std::exception& e) {
        if (threadList.list) {
            BridgeFree(threadList.list);
            threadList.list = nullptr;
        }
        LOG_ERROR("Failed to get thread list: {}", e.what());
        throw;
    }

    return threads;
}

uint32_t ThreadManager::GetCurrentThreadId() {
    if (!DbgIsDebugging()) {
        throw DebuggerNotRunningException("Debugger is not debugging");
    }

    DWORD tid = DbgGetThreadId();
    if (tid == 0) {
        THREADLIST threadList;
        memset(&threadList, 0, sizeof(THREADLIST));
        DbgGetThreadList(&threadList);

        if (threadList.list != nullptr &&
            threadList.count > 0 &&
            threadList.CurrentThread >= 0 &&
            threadList.CurrentThread < threadList.count) {
            tid = static_cast<DWORD>(threadList.list[threadList.CurrentThread].BasicInfo.ThreadId);
        }

        if (threadList.list) {
            BridgeFree(threadList.list);
        }
    }

    return static_cast<uint32_t>(tid);
}

ThreadInfo ThreadManager::GetCurrentThread() {
    uint32_t currentTID = GetCurrentThreadId();
    return GetThread(currentTID);
}

ThreadInfo ThreadManager::GetThread(uint32_t threadId) {
    // Get all threads and locate target ID.
    auto threads = GetThreadList();

    auto it = std::find_if(threads.begin(), threads.end(),
        [threadId](const ThreadInfo& info) {
            return info.id == threadId;
        });

    if (it == threads.end()) {
        throw ResourceNotFoundException("Thread not found: " + std::to_string(threadId));
    }

    return *it;
}

bool ThreadManager::SwitchThread(uint32_t threadId) {
    if (!DbgIsDebugging()) {
        throw DebuggerNotRunningException("Debugger is not debugging");
    }

    if (!IsValidThread(threadId)) {
        LOG_ERROR("Invalid thread ID: {}", threadId);
        return false;
    }

    if (GetCurrentThreadId() == threadId) {
        LOG_DEBUG("Already on thread {}", threadId);
        return true;
    }

    try {
        std::ostringstream cmdBuilder;
        cmdBuilder << "switchthread 0x" << std::hex << std::uppercase << threadId;
        std::string cmd = cmdBuilder.str();
        if (!DbgCmdExecDirect(cmd.c_str())) {
            LOG_ERROR("Failed to execute switch command for thread {}", threadId);
            return false;
        }

        // Wait until debugger state reflects the actual current thread.
        constexpr int kMaxPollCount = 50;
        constexpr DWORD kPollIntervalMs = 10;
        for (int i = 0; i < kMaxPollCount; ++i) {
            if (GetCurrentThreadId() == threadId) {
                LOG_INFO("Switched to thread {}", threadId);
                return true;
            }
            Sleep(kPollIntervalMs);
        }

        uint32_t actualThreadId = GetCurrentThreadId();
        LOG_ERROR("Thread switch timed out. expected={}, actual={}", threadId, actualThreadId);
        return false;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to switch thread: {}", e.what());
        return false;
    }
}

bool ThreadManager::SuspendThread(uint32_t threadId) {
    if (!DbgIsDebugging()) {
        throw DebuggerNotRunningException("Debugger is not debugging");
    }

    std::ostringstream cmdBuilder;
    cmdBuilder << "suspendthread 0x" << std::hex << std::uppercase << threadId;
    std::string cmd = cmdBuilder.str();
    return DbgCmdExec(cmd.c_str());
}

bool ThreadManager::ResumeThread(uint32_t threadId) {
    if (!DbgIsDebugging()) {
        throw DebuggerNotRunningException("Debugger is not debugging");
    }

    std::ostringstream cmdBuilder;
    cmdBuilder << "resumethread 0x" << std::hex << std::uppercase << threadId;
    std::string cmd = cmdBuilder.str();
    return DbgCmdExec(cmd.c_str());
}

size_t ThreadManager::GetThreadCount() {
    if (!DbgIsDebugging()) {
        return 0;
    }

    try {
        return GetThreadList().size();
    } catch (...) {
        return 0;
    }
}

bool ThreadManager::IsValidThread(uint32_t threadId) {
    if (!DbgIsDebugging()) {
        return false;
    }

    try {
        auto threads = GetThreadList();
        return std::any_of(threads.begin(), threads.end(),
            [threadId](const ThreadInfo& info) {
                return info.id == threadId;
            });
    } catch (...) {
        return false;
    }
}

std::string ThreadManager::GetThreadName(uint32_t threadId) {
    // Keep a stable fallback name even when thread description is unavailable.
    return "Thread " + std::to_string(threadId);
}

} // namespace MCP
