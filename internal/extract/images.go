package extract

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
)

const maxMultipartParts = 64

// imagesJSON handles /v1/images/generations and JSON /v1/images/edits bodies.
func (c *collector) imagesJSON(root map[string]any) error {
	msg := c.nextMsg()
	prompt, ok := str(root["prompt"])
	if !ok && root["prompt"] != nil {
		return invalid("prompt must be a string")
	}
	c.text("user", msg, prompt)
	addRef := func(v any) error {
		switch r := v.(type) {
		case string:
			return c.imageURL("user", msg, r)
		case map[string]any:
			if s, ok := str(r["image_url"]); ok {
				return c.imageURL("user", msg, s)
			}
			if s, ok := str(obj(r["image_url"])["url"]); ok {
				return c.imageURL("user", msg, s)
			}
			if s, ok := str(r["url"]); ok {
				return c.imageURL("user", msg, s)
			}
			c.unsupported("image reference without URL cannot be moderated")
		default:
			return invalid("image references must be strings or objects")
		}
		return nil
	}
	for _, field := range []string{"image", "images", "mask"} {
		switch v := root[field].(type) {
		case nil:
		case []any:
			for _, it := range v {
				if err := addRef(it); err != nil {
					return err
				}
			}
		default:
			if err := addRef(v); err != nil {
				return err
			}
		}
	}
	if strings.TrimSpace(prompt) == "" && len(c.out.Images) == 0 {
		c.unsupported("image request has no prompt")
	}
	return nil
}

// multipartImages handles multipart /v1/images/edits bodies without changing them.
func (c *collector) multipartImages(contentType string, body []byte) error {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return invalid("multipart body has no boundary")
	}
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	msg := c.nextMsg()
	parts := 0
	sawPrompt := false
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return invalid("malformed multipart body")
		}
		parts++
		if parts > maxMultipartParts {
			return tooLarge("multipart body has more than %d parts", maxMultipartParts)
		}
		name := part.FormName()
		limit := int64(c.opt.Limits.MaxImageBytes)
		if part.FileName() == "" {
			limit = int64(c.opt.Limits.MaxTextBytes)
		}
		if limit <= 0 {
			limit = 32 << 20
		}
		data, err := io.ReadAll(io.LimitReader(part, limit+1))
		part.Close()
		if err != nil {
			return invalid("malformed multipart body")
		}
		if int64(len(data)) > limit {
			return tooLarge("multipart field %q exceeds %d bytes", name, limit)
		}
		base := strings.TrimSuffix(name, "[]")
		switch {
		case part.FileName() == "" && name == "prompt":
			sawPrompt = true
			c.text("user", msg, string(data))
		case part.FileName() == "":
			// Plain form fields such as model, size, n are parameters, not content.
		case base == "image" || base == "mask" || base == "images":
			mt := part.Header.Get("Content-Type")
			if parsed, _, err := mime.ParseMediaType(mt); err == nil {
				mt = parsed
			}
			sniffed := http.DetectContentType(data)
			if !allowedImageMIME[strings.ToLower(mt)] {
				mt = sniffed
			}
			if mt != sniffed && allowedImageMIME[sniffed] {
				mt = sniffed // trust the bytes over the declared type
			}
			if err := c.imageBytes("user", msg, mt, data); err != nil {
				return err
			}
		default:
			c.unsupported("uploaded file field %q cannot be moderated", name)
		}
	}
	if !sawPrompt && len(c.out.Images) == 0 {
		c.unsupported("image request has no prompt")
	}
	return nil
}
