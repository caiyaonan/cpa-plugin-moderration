//go:build cshared

// Command cpa-moderation only marshals between the CLIProxyAPI plugin C ABI
// and internal/plugin. Build with: go build -tags cshared -buildmode=c-shared
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

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) { stored_host = host; }

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return -1;
	}
	return ((cliproxy_host_call_fn)stored_host->call)(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		((cliproxy_host_free_fn)stored_host->free_buffer)(ptr, len);
	}
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	"cpa-moderation/internal/plugin"
)

var app = plugin.NewApp()

func main() {}

// callHost invokes a host callback (e.g. host.auth.models) and returns the raw
// response envelope bytes.
func callHost(method string, payload []byte) ([]byte, error) {
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var req unsafe.Pointer
	if len(payload) > 0 {
		req = C.CBytes(payload)
		defer C.free(req)
	}
	var resp C.cliproxy_buffer
	code := C.call_host_api(cMethod, (*C.uint8_t)(req), C.size_t(len(payload)), &resp)
	if code == -1 {
		return nil, errors.New("host callbacks are not available")
	}
	if resp.ptr != nil {
		defer C.free_host_buffer(resp.ptr, resp.len)
	}
	if resp.ptr == nil || resp.len == 0 {
		return nil, fmt.Errorf("host call %s returned no response (code %d)", method, int(code))
	}
	if resp.len > C.size_t(64<<20) {
		return nil, fmt.Errorf("host call %s response is too large", method)
	}
	return C.GoBytes(resp.ptr, C.int(resp.len)), nil
}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, api *C.cliproxy_plugin_api) C.int {
	if api == nil {
		return 1
	}
	C.store_host_api(host)
	if host != nil {
		app.SetHostCaller(callHost)
	}
	api.abi_version = C.uint32_t(plugin.ABIVersion)
	api.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	api.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	api.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) (code C.int) {
	if response == nil {
		return 1
	}
	response.ptr = nil
	response.len = 0
	// Last-resort guard: app.HandleMethod already recovers, but nothing may
	// panic across the C boundary because it would kill the host process.
	defer func() {
		if r := recover(); r != nil {
			code = 1
		}
	}()
	if method == nil {
		return 1
	}
	var body []byte
	if request != nil && requestLen > 0 {
		length := C.int(requestLen)
		if length < 0 || C.size_t(length) != requestLen {
			return 1
		}
		body = C.GoBytes(unsafe.Pointer(request), length)
	}
	raw := app.HandleMethod(C.GoString(method), body)
	if len(raw) > 0 {
		response.ptr = C.CBytes(raw)
		response.len = C.size_t(len(raw))
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
func cliproxyPluginShutdown() {
	defer func() { _ = recover() }()
	app.Shutdown()
}
