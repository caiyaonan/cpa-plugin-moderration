//go:build cshared

// Command cpa-mod-probe is a PoC plugin: it records what CLIProxyAPI passes to
// request interceptors and exercises the termination / error paths.
//
// Body markers (only for PoC testing):
//
//	PROBE_BLOCK  -> Terminate with 403 (must never reach upstream)
//	PROBE_ERROR  -> return an error envelope (checks host fail-open)
//	PROBE_PANIC  -> panic inside the plugin (checks whether the host process survives)
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	void* call;
	void* free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"unsafe"
)

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(_ *C.cliproxy_host_api, api *C.cliproxy_plugin_api) C.int {
	if api == nil {
		return 1
	}
	api.abi_version = C.uint32_t(abiVersion)
	api.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	api.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	api.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response == nil {
		return 1
	}
	response.ptr = nil
	response.len = 0
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required", 400))
		return 1
	}
	var body []byte
	if request != nil && requestLen > 0 {
		body = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, failed := handleMethod(C.GoString(method), body)
	writeResponse(response, raw)
	if failed {
		return 1
	}
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() { closeLog() }

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if len(raw) == 0 {
		return
	}
	response.ptr = C.CBytes(raw)
	response.len = C.size_t(len(raw))
}
