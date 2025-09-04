#include "webview.h"

#include <stdlib.h>
#include <stdint.h>

struct binding_context {
    webview_t w;
    uintptr_t index;
};

struct uri_scheme_context {
    webview_t w;
    uintptr_t index;
};

void _webviewDispatchGoCallback(void *);
void _webviewBindingGoCallback(webview_t, char *, char *, uintptr_t);
void _webviewUriSchemeGoCallback(webview_t, char *, char *, unsigned long, uintptr_t);

static void _webview_dispatch_cb(webview_t w, void *arg) {
    _webviewDispatchGoCallback(arg);
}

static void _webview_binding_cb(const char *id, const char *req, void *arg) {
    struct binding_context *ctx = (struct binding_context *) arg;
    _webviewBindingGoCallback(ctx->w, (char *)id, (char *)req, ctx->index);
}

// URI scheme callback function that webview library calls
void _webview_uri_scheme_cb(const char* uri, const char* path, unsigned long request_id, void *arg, unsigned long index) {
    // Extract the webview instance from the arg (which is the engine pointer)
    webview_t w = (webview_t)arg;
    _webviewUriSchemeGoCallback(w, (char *)uri, (char *)path, request_id, index);
}

void CgoWebViewDispatch(webview_t w, uintptr_t arg) {
    webview_dispatch(w, _webview_dispatch_cb, (void *)arg);
}

void CgoWebViewBind(webview_t w, const char *name, uintptr_t index) {
    struct binding_context *ctx = calloc(1, sizeof(struct binding_context));
    ctx->w = w;
    ctx->index = index;
    webview_bind(w, name, _webview_binding_cb, (void *)ctx);
}

void CgoWebViewUnbind(webview_t w, const char *name) {
    webview_unbind(w, name);
}

void CgoWebViewRegisterURIScheme(webview_t w, const char *scheme, uintptr_t index) {
    webview_register_uri_scheme(w, scheme, index);
}

void CgoWebViewUnregisterURIScheme(webview_t w, const char *scheme) {
    webview_unregister_uri_scheme(w, scheme);
}

void CgoWebViewURISchemeResponse(webview_t w, unsigned long request_id, int status, 
                                 const char *content_type, const char *data, size_t data_length) {
    webview_uri_scheme_response(w, request_id, status, content_type, data, data_length);
}
