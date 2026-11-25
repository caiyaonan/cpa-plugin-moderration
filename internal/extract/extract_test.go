package extract

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/textproto"
	"strings"
	"testing"
)

// 1x1 transparent PNG.
const pngB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

var defaultRoles = map[string]bool{"system": true, "user": true, "tool": true}

func opts() Options {
	return Options{Roles: defaultRoles, RemoteImages: "pass", Limits: Limits{MaxBodyBytes: 1 << 20, MaxTextBytes: 1 << 16, MaxImages: 4, MaxImageBytes: 1 << 20}}
}

func texts(c *Content) string {
	var parts []string
	for _, s := range c.Texts {
		parts = append(parts, s.Role+":"+s.Text)
	}
	return strings.Join(parts, "|")
}

func mustExtract(t *testing.T, format, ct, body string, o Options) *Content {
	t.Helper()
	c, err := Extract(format, ct, []byte(body), o)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	return c
}

func kindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

func TestChatMultiTurn(t *testing.T) {
	body := `{"model":"m","messages":[
	 {"role":"system","content":"S"},
	 {"role":"developer","content":"D"},
	 {"role":"user","content":"U1"},
	 {"role":"assistant","content":"A1","tool_calls":[{"function":{"name":"f","arguments":"{\"q\":1}"}}]},
	 {"role":"tool","content":[{"type":"text","text":"T1"}]},
	 {"role":"user","content":[{"type":"text","text":"U2"},{"type":"image_url","image_url":{"url":"data:image/png;base64,` + pngB64 + `"}}]}]}`
	c := mustExtract(t, "openai", "application/json", body, opts())
	if got := texts(c); got != "system:S|system:D|user:U1|tool:T1|user:U2" {
		t.Fatalf("texts=%q", got)
	}
	if len(c.Images) != 1 || c.Images[0].MIME != "image/png" || c.Images[0].Digest == "" {
		t.Fatalf("images=%+v", c.Images)
	}
	all := opts()
	all.Roles = nil
	c = mustExtract(t, "openai", "", body, all)
	if !strings.Contains(texts(c), "assistant:A1") || !strings.Contains(texts(c), `assistant:{"q":1}`) {
		t.Fatalf("assistant content missing: %q", texts(c))
	}
}

func TestHistoryLastN(t *testing.T) {
	body := `{"messages":[{"role":"system","content":"S"},{"role":"user","content":"old"},{"role":"user","content":"mid"},{"role":"user","content":"new"}]}`
	o := opts()
	o.HistoryLastN = 2
	c := mustExtract(t, "openai", "", body, o)
	if got := texts(c); got != "system:S|user:mid|user:new" {
		t.Fatalf("texts=%q", got)
	}
	if len(c.Notes) == 0 {
		t.Error("history trimming must be noted")
	}
}

func TestChatErrorsAndUnsupported(t *testing.T) {
	if _, err := Extract("openai", "", []byte(`not json`), opts()); kindOf(err) != KindInvalid {
		t.Errorf("bad json: %v", err)
	}
	bad := `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,@@@"}}]}]}`
	if _, err := Extract("openai", "", []byte(bad), opts()); kindOf(err) != KindInvalid {
		t.Errorf("bad base64: %v", err)
	}
	audio := `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"x"}}]}]}`
	c := mustExtract(t, "openai", "", audio, opts())
	if len(c.Unsupported) != 1 {
		t.Errorf("audio must be unsupported: %+v", c)
	}
	svg := `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/svg+xml;base64,PHN2Zz4="}}]}]}`
	c = mustExtract(t, "openai", "", svg, opts())
	if len(c.Unsupported) != 1 || len(c.Images) != 0 {
		t.Errorf("svg must be unsupported: %+v", c)
	}
	fileRef := `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"file-abc"}}]}]}`
	c = mustExtract(t, "openai", "", fileRef, opts())
	if len(c.Unsupported) != 1 {
		t.Errorf("file id must be unsupported: %+v", c)
	}
	c = mustExtract(t, "openai", "", `{"model":"x"}`, opts())
	if len(c.Unsupported) != 1 {
		t.Error("request without messages must be unsupported")
	}
}

func TestRemoteImages(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}`
	c := mustExtract(t, "openai", "", body, opts())
	if len(c.Images) != 1 || !c.Images[0].Remote {
		t.Fatalf("remote image: %+v", c.Images)
	}
	o := opts()
	o.RemoteImages = "deny"
	c = mustExtract(t, "openai", "", body, o)
	if len(c.Images) != 0 || len(c.Unsupported) != 1 {
		t.Fatalf("remote deny: %+v", c)
	}
}

func TestLimits(t *testing.T) {
	o := opts()
	o.Limits.MaxTextBytes = 5
	if _, err := Extract("openai", "", []byte(`{"messages":[{"role":"user","content":"123456"}]}`), o); kindOf(err) != KindTooLarge {
		t.Errorf("text limit: %v", err)
	}
	o = opts()
	o.Limits.MaxBodyBytes = 10
	if _, err := Extract("openai", "", []byte(`{"messages":[]}           `), o); kindOf(err) != KindTooLarge {
		t.Errorf("body limit: %v", err)
	}
	o = opts()
	o.Limits.MaxImages = 1
	img := `{"type":"image_url","image_url":{"url":"data:image/png;base64,` + pngB64 + `"}}`
	if _, err := Extract("openai", "", []byte(`{"messages":[{"role":"user","content":[`+img+`,`+img+`]}]}`), o); kindOf(err) != KindTooLarge {
		t.Errorf("image count: %v", err)
	}
	o = opts()
	o.Limits.MaxImageBytes = 10
	if _, err := Extract("openai", "", []byte(`{"messages":[{"role":"user","content":[`+img+`]}]}`), o); kindOf(err) != KindTooLarge {
		t.Errorf("image size: %v", err)
	}
}

func TestResponses(t *testing.T) {
	body := `{"model":"m","instructions":"INS","previous_response_id":"resp_1","input":[
	 {"role":"user","content":[{"type":"input_text","text":"hi"},{"type":"input_image","image_url":"data:image/png;base64,` + pngB64 + `"}]},
	 {"type":"function_call","name":"f","arguments":"{\"a\":1}"},
	 {"type":"function_call_output","call_id":"c","output":"tool says"},
	 {"type":"custom_tool_call_output","call_id":"d","output":[{"type":"input_text","text":"custom out"}]},
	 {"type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},
	 {"type":"item_reference","id":"x"}]}`
	c := mustExtract(t, "openai-response", "", body, opts())
	if got := texts(c); got != "system:INS|user:hi|tool:tool says|tool:custom out" {
		t.Fatalf("texts=%q", got)
	}
	if len(c.Images) != 1 || len(c.Unsupported) != 1 || len(c.Notes) != 1 {
		t.Fatalf("content=%+v", c)
	}
	c = mustExtract(t, "codex", "", `{"input":"plain"}`, opts())
	if texts(c) != "user:plain" {
		t.Fatalf("string input: %q", texts(c))
	}
}

func TestClaude(t *testing.T) {
	body := `{"model":"c","system":[{"type":"text","text":"SYS"}],"messages":[
	 {"role":"user","content":[{"type":"text","text":"U"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + pngB64 + `"}}]},
	 {"role":"assistant","content":[{"type":"thinking","thinking":"T"},{"type":"tool_use","id":"t","name":"f","input":{"k":"v"}}]},
	 {"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"RESULT"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + pngB64 + `"}}]}]},
	 {"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBER"}}]}]}`
	c := mustExtract(t, "claude", "", body, opts())
	if got := texts(c); got != "system:SYS|user:U|tool:RESULT" {
		t.Fatalf("texts=%q", got)
	}
	if len(c.Images) != 2 || len(c.Unsupported) != 1 {
		t.Fatalf("images=%d unsupported=%v", len(c.Images), c.Unsupported)
	}
	c = mustExtract(t, "claude-code", "", `{"messages":[{"role":"user","content":"hello"}]}`, opts())
	if texts(c) != "user:hello" {
		t.Fatal("claude variant format")
	}
	if _, err := Extract("claude", "", []byte(`{"messages":{}}`), opts()); kindOf(err) != KindInvalid {
		t.Errorf("invalid messages: %v", err)
	}
}

func TestGemini(t *testing.T) {
	body := `{"systemInstruction":{"parts":[{"text":"SYS"}]},"contents":[
	 {"role":"user","parts":[{"text":"U"},{"inlineData":{"mimeType":"image/png","data":"` + pngB64 + `"}}]},
	 {"role":"model","parts":[{"text":"M"},{"functionCall":{"name":"f","args":{"a":1}}}]},
	 {"role":"user","parts":[{"functionResponse":{"name":"f","response":{"r":"FR"}}},{"fileData":{"fileUri":"gs://x"}}]}]}`
	c := mustExtract(t, "gemini", "", body, opts())
	if got := texts(c); got != `system:SYS|user:U|tool:{"r":"FR"}` {
		t.Fatalf("texts=%q", got)
	}
	if len(c.Images) != 1 || len(c.Unsupported) != 1 {
		t.Fatalf("content=%+v", c)
	}
}

func TestImagesJSON(t *testing.T) {
	c := mustExtract(t, "openai-image", "application/json", `{"model":"gpt-image-1","prompt":"a cat"}`, opts())
	if texts(c) != "user:a cat" {
		t.Fatal(texts(c))
	}
	c = mustExtract(t, "openai-image", "application/json", `{"prompt":"edit","images":[{"image_url":"data:image/png;base64,`+pngB64+`"}],"mask":"data:image/png;base64,`+pngB64+`"}`, opts())
	if len(c.Images) != 2 {
		t.Fatalf("images=%d", len(c.Images))
	}
}

func TestImagesMultipart(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("model", "gpt-image-1")
	_ = w.WriteField("prompt", "edit this")
	png := decodeOrDie(t, pngB64)
	for i := 0; i < 2; i++ {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="image[]"; filename="a.png"`)
		h.Set("Content-Type", "application/octet-stream") // wrong type: sniffing must fix it
		p, _ := w.CreatePart(h)
		_, _ = p.Write(png)
	}
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="extra"; filename="a.bin"`)
	p, _ := w.CreatePart(h)
	_, _ = p.Write([]byte("binary"))
	_ = w.Close()
	original := append([]byte(nil), buf.Bytes()...)

	c := mustExtract(t, "openai-image", w.FormDataContentType(), buf.String(), opts())
	if texts(c) != "user:edit this" || len(c.Images) != 2 || len(c.Unsupported) != 1 {
		t.Fatalf("content=%+v", c)
	}
	if !bytes.Equal(original, buf.Bytes()) {
		t.Fatal("extraction must not modify the body")
	}
	if _, err := Extract("openai-image", "multipart/form-data", buf.Bytes(), opts()); kindOf(err) != KindInvalid {
		t.Errorf("missing boundary: %v", err)
	}
}

func TestUnknownFormat(t *testing.T) {
	c := mustExtract(t, "soap", "", `{}`, opts())
	if len(c.Unsupported) != 1 {
		t.Fatal("unknown format must be unsupported")
	}
}

func decodeOrDie(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decodeBase64(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
