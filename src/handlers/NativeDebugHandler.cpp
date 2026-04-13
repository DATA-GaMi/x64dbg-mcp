#include "NativeDebugHandler.h"
#include "../core/MethodDispatcher.h"
#include "../core/Exceptions.h"
#pragma warning(push)
#pragma warning(disable: 4324)
#include "../core/X64DBGBridge.h"
#pragma warning(pop)
#include "../utils/StringUtils.h"
#include "../../include/x64dbg-pluginsdk/bridgelist.h"
#include <limits>

namespace MCP {

namespace {

std::string XrefTypeToString(XREFTYPE type) {
    switch (type) {
    case XREF_DATA:
        return "data";
    case XREF_JMP:
        return "jump";
    case XREF_CALL:
        return "call";
    case XREF_NONE:
    default:
        return "none";
    }
}

void EnsureAddressParam(const nlohmann::json& params) {
    if (!params.contains("address")) {
        throw InvalidParamsException("Missing required parameter: address");
    }
}

uint64_t ParseAddressParam(const nlohmann::json& params) {
    EnsureAddressParam(params);
    return StringUtils::ParseAddress(params["address"].get<std::string>());
}

void EnsureDbgFunctionsAvailable() {
    if (!DbgFunctions()) {
        throw MCPException("DbgFunctions is not available");
    }
}

duint ToDbgAddress(uint64_t address) {
#ifdef XDBG_ARCH_X86
    if (address > std::numeric_limits<duint>::max()) {
        throw InvalidAddressException("Address is out of range for x86 target: " + StringUtils::FormatAddress(address));
    }
#endif
    return static_cast<duint>(address);
}

} // namespace

void NativeDebugHandler::RegisterMethods() {
    auto& dispatcher = MethodDispatcher::Instance();
    dispatcher.RegisterMethod("native.get_xrefs", GetXrefs);
    dispatcher.RegisterMethod("native.get_xref_count", GetXrefCount);
    dispatcher.RegisterMethod("native.list_patches", ListPatches);
    dispatcher.RegisterMethod("native.get_patch_at", GetPatchAt);
    dispatcher.RegisterMethod("native.enum_handles", EnumHandles);
    dispatcher.RegisterMethod("native.enum_tcp_connections", EnumTcpConnections);
}

nlohmann::json NativeDebugHandler::GetXrefs(const nlohmann::json& params) {
    const uint64_t address = ParseAddressParam(params);
    const duint dbgAddress = ToDbgAddress(address);

    XREF_INFO info{};
    if (!DbgXrefGet(dbgAddress, &info)) {
        const auto refCount = DbgGetXrefCountAt(dbgAddress);
        if (refCount == 0) {
            return {
                {"address", StringUtils::FormatAddress(address)},
                {"count", 0},
                {"references", nlohmann::json::array()}
            };
        }
        throw MCPException("Failed to query xrefs at address");
    }

    nlohmann::json refs = nlohmann::json::array();
    for (duint i = 0; i < info.refcount; ++i) {
        const auto& ref = info.references[i];
        refs.push_back({
            {"address", StringUtils::FormatAddress(ref.addr)},
            {"type", XrefTypeToString(ref.type)}
        });
    }

    if (info.references) {
        BridgeFree(info.references);
    }

    return {
        {"address", StringUtils::FormatAddress(address)},
        {"count", info.refcount},
        {"references", refs}
    };
}

nlohmann::json NativeDebugHandler::GetXrefCount(const nlohmann::json& params) {
    const uint64_t address = ParseAddressParam(params);
    const duint dbgAddress = ToDbgAddress(address);
    return {
        {"address", StringUtils::FormatAddress(address)},
        {"count", DbgGetXrefCountAt(dbgAddress)}
    };
}

nlohmann::json NativeDebugHandler::ListPatches(const nlohmann::json& params) {
    (void)params;
    EnsureDbgFunctionsAvailable();
    if (!DbgFunctions()->PatchEnum) {
        throw MCPException("Patch enumeration is not available in this x64dbg build");
    }

    size_t patchBytes = 0;
    if (!DbgFunctions()->PatchEnum(nullptr, &patchBytes)) {
        throw MCPException("Failed to query patch enumeration size");
    }

    const size_t patchCount = patchBytes / sizeof(DBGPATCHINFO);
    std::vector<DBGPATCHINFO> patchBuffer(patchCount);
    if (patchBytes != 0 && !DbgFunctions()->PatchEnum(patchBuffer.data(), &patchBytes)) {
        throw MCPException("Failed to enumerate patches");
    }

    nlohmann::json patches = nlohmann::json::array();
    for (const auto& patch : patchBuffer) {
        patches.push_back({
            {"module", patch.mod},
            {"address", StringUtils::FormatAddress(patch.addr)},
            {"old_byte", StringUtils::BytesToHex(&patch.oldbyte, 1)},
            {"new_byte", StringUtils::BytesToHex(&patch.newbyte, 1)}
        });
    }

    return {
        {"count", patchBuffer.size()},
        {"patches", patches}
    };
}

nlohmann::json NativeDebugHandler::GetPatchAt(const nlohmann::json& params) {
    const uint64_t address = ParseAddressParam(params);
    const duint dbgAddress = ToDbgAddress(address);
    EnsureDbgFunctionsAvailable();
    if (!DbgFunctions()->PatchGetEx) {
        throw MCPException("Patch lookup is not available in this x64dbg build");
    }

    DBGPATCHINFO patch{};
    if (!DbgFunctions()->PatchGetEx(dbgAddress, &patch)) {
        throw ResourceNotFoundException("No patch found at address");
    }

    return {
        {"module", patch.mod},
        {"address", StringUtils::FormatAddress(patch.addr)},
        {"old_byte", StringUtils::BytesToHex(&patch.oldbyte, 1)},
        {"new_byte", StringUtils::BytesToHex(&patch.newbyte, 1)}
    };
}

nlohmann::json NativeDebugHandler::EnumHandles(const nlohmann::json& params) {
    (void)params;
    EnsureDbgFunctionsAvailable();
    if (!DbgFunctions()->EnumHandles) {
        throw MCPException("Handle enumeration is not available in this x64dbg build");
    }

    BridgeList<HANDLEINFO> handles;
    if (!DbgFunctions()->EnumHandles(&handles)) {
        throw MCPException("Failed to enumerate handles");
    }

    nlohmann::json items = nlohmann::json::array();
    for (int i = 0; i < handles.Count(); ++i) {
        const auto& handle = handles[i];
        nlohmann::json item = {
            {"handle", StringUtils::FormatAddress(handle.Handle)},
            {"type_number", handle.TypeNumber},
            {"granted_access", handle.GrantedAccess}
        };

        if (DbgFunctions()->GetHandleName) {
            char name[512] = {};
            char typeName[128] = {};
            if (DbgFunctions()->GetHandleName(handle.Handle, name, sizeof(name), typeName, sizeof(typeName))) {
                item["name"] = name;
                item["type_name"] = typeName;
            }
        }

        items.push_back(item);
    }

    return {
        {"count", handles.Count()},
        {"handles", items}
    };
}

nlohmann::json NativeDebugHandler::EnumTcpConnections(const nlohmann::json& params) {
    (void)params;
    EnsureDbgFunctionsAvailable();
    if (!DbgFunctions()->EnumTcpConnections) {
        throw MCPException("TCP connection enumeration is not available in this x64dbg build");
    }

    BridgeList<TCPCONNECTIONINFO> connections;
    if (!DbgFunctions()->EnumTcpConnections(&connections)) {
        throw MCPException("Failed to enumerate TCP connections");
    }

    nlohmann::json items = nlohmann::json::array();
    for (int i = 0; i < connections.Count(); ++i) {
        const auto& connection = connections[i];
        items.push_back({
            {"remote_address", connection.RemoteAddress},
            {"remote_port", connection.RemotePort},
            {"local_address", connection.LocalAddress},
            {"local_port", connection.LocalPort},
            {"state_text", connection.StateText},
            {"state", connection.State}
        });
    }

    return {
        {"count", connections.Count()},
        {"connections", items}
    };
}

} // namespace MCP
