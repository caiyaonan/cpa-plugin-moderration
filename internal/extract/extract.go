// Package extract pulls the text and images that must be moderated out of a
// raw client request, per CLIProxyAPI source format. It never modifies the body.
package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"strings"
)

type Kind string

const (
	KindInvalid  Kind = "invalid"
	KindTooLarge Kind = "too_large"
)

type Error struct {
	Kind Kind
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &Error{Kind: KindInvalid, Msg: fmt.Sprintf(format, args...)}
}

func tooLarge(format string, args ...any) error {
	return &Error{Kind: KindTooLarge, Msg: fmt.Sprintf(format, args...)}
}

type Limits struct {
	MaxBodyBytes  int
	MaxTextBytes  int
	MaxImages     int
	MaxImageBytes int
}

type Options struct {
	Roles        map[string]bool // nil = every role
	HistoryLastN int             // 0 = whole history
	RemoteImages string          // "pass" or "deny"
	Limits       Limits
}

type Segment struct {
	Role string
	Text string
	msg  int
}

type Image struct {
	Role   string
	URL    string // data: URL or remote http(s) URL
	Remote bool
	MIME   string
	Bytes  int
	Digest string // sha256 of decoded bytes (data URLs only)
	msg    int
}

type Content struct {
	Texts       []Segment
	Images      []Image
	Unsupported []string // content that cannot be moderated
	Notes       []string // coverage limitations worth auditing
}

func (c *Content) TextBytes() int {
	n := 0
	for _, s := range c.Texts {
		n += len(s.Text)
	}
	return n
}

var allowedImageMIME = map[string]bool{
	"image/png":  true,
	"image/jpeg": true,
	"image/gif":  true,
	"image/webp": true,
}

// Extract parses body according to format. contentType is the request
// Content-Type header (needed for multipart bodies).
func Extract(format, contentType string, body []byte, opt Options) (*Content, error) {
	if opt.Limits.MaxBodyBytes > 0 && len(body) > opt.Limits.MaxBodyBytes {
		return nil, tooLarge("request body is %d bytes, limit is %d", len(body), opt.Limits.MaxBodyBytes)
	}
	c := &collector{opt: opt, out: &Content{}}
	var err error
	switch normalizeFormat(format) {
	case "openai":
		err = c.withJSON(body, c.openAIChat)
	case "openai-response":
		err = c.withJSON(body, c.responses)
	case "openai-image":
		if isMultipart(contentType) {
			err = c.multipartImages(contentType, body)
		} else {
			err = c.withJSON(body, c.imagesJSON)
		}
	case "claude":
		err = c.withJSON(body, c.claude)
	case "gemini":
		err = c.withJSON(body, c.gemini)
	default:
		c.unsupported("source format %q is not supported", format)
	}
	if err != nil {
		return nil, err
	}
	return c.finish()
}

func normalizeFormat(f string) string {
	f = strings.ToLower(strings.TrimSpace(f))
	switch {
	case f == "openai" || f == "openai-chat":
		return "openai"
	case f == "openai-response" || f == "openai-responses" || f == "codex":
		return "openai-response"
	case f == "openai-image" || f == "openai-images":
		return "openai-image"
	case strings.Contains(f, "claude") || strings.Contains(f, "anthropic"):
		return "claude"
	case f == "gemini" || f == "gemini-cli" || f == "aistudio":
		return "gemini"
	}
	return f
}

func isMultipart(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.HasPrefix(mt, "multipart/")
}

type collector struct {
	opt  Options
	out  *Content
	msgs int // message ordinal counter for history filtering
}

func (c *collector) withJSON(body []byte, fn func(map[string]any) error) error {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return invalid("request body is empty")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var root any
	if err := dec.Decode(&root); err != nil {
		return invalid("request body is not valid JSON")
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return invalid("request body must be a JSON object")
	}
	return fn(obj)
}

// nextMsg allocates an ordinal for a conversation message. System prompts use -1
// so history trimming never drops them.
func (c *collector) nextMsg() int {
	n := c.msgs
	c.msgs++
	return n
}

func (c *collector) roleAllowed(role string) bool {
	return c.opt.Roles == nil || c.opt.Roles[role]
}

func (c *collector) text(role string, msg int, s string) {
	if strings.TrimSpace(s) == "" || !c.roleAllowed(role) {
		return
	}
	c.out.Texts = append(c.out.Texts, Segment{Role: role, Text: s, msg: msg})
}

func (c *collector) unsupported(format string, args ...any) {
	c.out.Unsupported = append(c.out.Unsupported, fmt.Sprintf(format, args...))
}

func (c *collector) note(format string, args ...any) {
	c.out.Notes = append(c.out.Notes, fmt.Sprintf(format, args...))
}

// imageURL handles data: URLs and remote URLs; anything else is unsupported.
func (c *collector) imageURL(role string, msg int, raw string) error {
	if !c.roleAllowed(role) {
		return nil
	}
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "data:"):
		mt, data, err := parseDataURL(raw)
		if err != nil {
			return err
		}
		return c.imageBytes(role, msg, mt, data)
	case strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://"):
		if c.opt.RemoteImages != "pass" {
			c.unsupported("remote image URLs are not allowed")
			return nil
		}
		c.out.Images = append(c.out.Images, Image{Role: role, URL: raw, Remote: true, msg: msg})
		return nil
	case raw == "":
		return invalid("image URL is empty")
	default:
		c.unsupported("image reference type cannot be moderated")
		return nil
	}
}

func (c *collector) imageBytes(role string, msg int, mimeType string, data []byte) error {
	if !c.roleAllowed(role) {
		return nil
	}
	mimeType = strings.ToLower(strings.TrimSpace(mimeType))
	if !allowedImageMIME[mimeType] {
		c.unsupported("image type %q cannot be moderated", mimeType)
		return nil
	}
	if c.opt.Limits.MaxImageBytes > 0 && len(data) > c.opt.Limits.MaxImageBytes {
		return tooLarge("image is %d bytes, limit is %d", len(data), c.opt.Limits.MaxImageBytes)
	}
	if len(data) == 0 {
		return invalid("image is empty")
	}
	sum := sha256.Sum256(data)
	c.out.Images = append(c.out.Images, Image{
		Role:   role,
		URL:    "data:" + mimeType + ";base64," + base64.StdEncoding.EncodeToString(data),
		MIME:   mimeType,
		Bytes:  len(data),
		Digest: hex.EncodeToString(sum[:]),
		msg:    msg,
	})
	return nil
}

func parseDataURL(raw string) (string, []byte, error) {
	comma := strings.IndexByte(raw, ',')
	if comma < 0 {
		return "", nil, invalid("malformed data URL")
	}
	meta := raw[len("data:"):comma]
	payload := raw[comma+1:]
	parts := strings.Split(meta, ";")
	if len(parts) < 2 || !strings.EqualFold(parts[len(parts)-1], "base64") {
		return "", nil, invalid("data URL must be base64 encoded")
	}
	data, err := decodeBase64(payload)
	if err != nil {
		return "", nil, invalid("data URL contains invalid base64")
	}
	return parts[0], data, nil
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if data, err := enc.DecodeString(s); err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

func (c *collector) finish() (*Content, error) {
	out := c.out
	if n := c.opt.HistoryLastN; n > 0 && c.msgs > n {
		cut := c.msgs - n
		texts := out.Texts[:0]
		for _, s := range out.Texts {
			if s.msg < 0 || s.msg >= cut {
				texts = append(texts, s)
			}
		}
		out.Texts = texts
		images := out.Images[:0]
		for _, im := range out.Images {
			if im.msg < 0 || im.msg >= cut {
				images = append(images, im)
			}
		}
		out.Images = images
		out.Notes = append(out.Notes, fmt.Sprintf("only the last %d messages were moderated", n))
	}
	if lim := c.opt.Limits.MaxTextBytes; lim > 0 && out.TextBytes() > lim {
		return nil, tooLarge("text to moderate is %d bytes, limit is %d", out.TextBytes(), lim)
	}
	if lim := c.opt.Limits.MaxImages; lim > 0 && len(out.Images) > lim {
		return nil, tooLarge("request has %d images, limit is %d", len(out.Images), lim)
	}
	return out, nil
}

// --- small JSON helpers ---

func str(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func arr(v any) []any {
	a, _ := v.([]any)
	return a
}

func compactJSON(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "system", "developer":
		return "system"
	case "assistant", "model":
		return "assistant"
	case "tool", "function":
		return "tool"
	default:
		// Unknown or missing roles are treated as user input so they are moderated.
		return "user"
	}
}

// NormalizeFormat maps CLIProxyAPI source format names (and known variants)
// to the formats used by policy rules.
func NormalizeFormat(f string) string { return normalizeFormat(f) }
