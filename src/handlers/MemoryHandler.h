#pragma once
#include <nlohmann/json.hpp>
#include <string>

namespace MCP {

/**
 * @brief 内存操作的 JSON-RPC 处理器
 * 
 * 实现的方法：
 * - memory.read: 读取内存
 * - memory.write: 写入内存
 * - memory.search: 搜索内存模式
 * - memory.get_info: 获取内存信息
 * - memory.enumerate: 枚举内存区域
 * - memory.allocate: 分配内存
 * - memory.free: 释放内存
 * - memory.set_protection: 修改内存页保护
 */
class MemoryHandler {
public:
    /**
     * @brief 注册所有内存相关的方法
     */
    static void RegisterMethods();

private:
    /**
     * @brief 读取内存
     * @param params { "address": "0x401000", "size": 100, "encoding": "hex" }
     * @return { "address": "0x401000", "size": 100, "data": "4883EC20...", "encoding": "hex" }
     */
    static nlohmann::json Read(const nlohmann::json& params);
    
    /**
     * @brief 写入内存
     * @param params { "address": "0x401000", "data": "4883EC20", "encoding": "hex" }
     * @return { "address": "0x401000", "bytes_written": 4 }
     */
    static nlohmann::json Write(const nlohmann::json& params);
    
    /**
     * @brief 搜索内存模式
     * @param params { "pattern": "48 83 EC ??", "start": "0x400000", "end": "0x500000", "max_results": 100 }
     * @return { "results": [{"address": "0x401234", "data": "4883EC20"}] }
     */
    static nlohmann::json Search(const nlohmann::json& params);
    
    /**
     * @brief 获取内存信息
     * @param params { "address": "0x401000" }
     * @return { "base": "0x400000", "size": 4096, "protection": "PAGE_EXECUTE_READ", ... }
     */
    static nlohmann::json GetInfo(const nlohmann::json& params);
    
    /**
     * @brief 枚举内存区域
     * @param params {}
     * @return { "regions": [...] }
     */
    static nlohmann::json Enumerate(const nlohmann::json& params);
    
    /**
     * @brief 分配内存
     * @param params { "size": 4096 }
     * @return { "address": "0x10000000", "size": 4096 }
     */
    static nlohmann::json Allocate(const nlohmann::json& params);
    
    /**
     * @brief 释放内存
     * @param params { "address": "0x10000000" }
     * @return { "success": true }
     */
    static nlohmann::json Free(const nlohmann::json& params);

    /**
     * @brief 修改内存页保护
     * @param params { "address": "0x401000", "protection": "PAGE_EXECUTE_READ" }
     * @return { "address": "0x401000", "old_protection": "...", "new_protection": "..." }
     */
    static nlohmann::json SetProtection(const nlohmann::json& params);
    
    // 辅助方法
    static std::vector<uint8_t> DecodeData(const std::string& data, const std::string& encoding);
    static std::string EncodeData(const std::vector<uint8_t>& data, const std::string& encoding);
};

} // namespace MCP
