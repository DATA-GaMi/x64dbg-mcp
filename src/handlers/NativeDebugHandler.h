#pragma once
#include <nlohmann/json.hpp>

namespace MCP {

class NativeDebugHandler {
public:
    static void RegisterMethods();

private:
    static nlohmann::json GetXrefs(const nlohmann::json& params);
    static nlohmann::json GetXrefCount(const nlohmann::json& params);
    static nlohmann::json ListPatches(const nlohmann::json& params);
    static nlohmann::json GetPatchAt(const nlohmann::json& params);
    static nlohmann::json EnumHandles(const nlohmann::json& params);
    static nlohmann::json EnumTcpConnections(const nlohmann::json& params);
};

} // namespace MCP
