package extract

import (
	"strings"
)

// genericPart handles part types this package does not know: any "text" string
// is moderated; otherwise the part is reported as unsupported.
func (c *collector) genericPart(role string, msg int, part map[string]any, kind string) {
	if s, ok := str(part["text"]); ok {
		c.text(role, msg, s)
		return
	}
	if !c.roleAllowed(role) {
		return
	}
	c.unsupported("content part type %q cannot be moderated", kind)
}

// ---------------- OpenAI chat completions ----------------

func (c *collector) openAIChat(root map[string]any) error {
	msgs, hasMsgs := root["messages"]
	if hasMsgs {
		list := arr(msgs)
		if list == nil {
			return invalid("messages must be an array")
		}
		for _, item := range list {
			m := obj(item)
			if m == nil {
				return invalid("each message must be an object")
			}
			role := normalizeRole(stringOr(m["role"]))
			msg := -1
			if role != "system" {
				msg = c.nextMsg()
			}
			if err := c.chatContent(role, msg, m["content"]); err != nil {
				return err
			}
			if s, ok := str(m["refusal"]); ok {
				c.text(role, msg, s)
			}
			for _, tc := range arr(m["tool_calls"]) {
				if fn := obj(obj(tc)["function"]); fn != nil {
					c.text(role, msg, compactJSON(fn["arguments"]))
				}
			}
			if fc := obj(m["function_call"]); fc != nil {
				c.text(role, msg, compactJSON(fc["arguments"]))
			}
		}
		return nil
	}
	if prompt, ok := root["prompt"]; ok { // legacy completions
		msg := c.nextMsg()
		switch p := prompt.(type) {
		case string:
			c.text("user", msg, p)
		case []any:
			for _, v := range p {
				if s, ok := str(v); ok {
					c.text("user", msg, s)
				} else {
					c.unsupported("token-array prompts cannot be moderated")
				}
			}
		default:
			return invalid("prompt must be a string or array")
		}
		return nil
	}
	c.unsupported("request has neither messages nor prompt")
	return nil
}

func (c *collector) chatContent(role string, msg int, content any) error {
	switch v := content.(type) {
	case nil:
		return nil
	case string:
		c.text(role, msg, v)
		return nil
	case []any:
		for _, p := range v {
			part := obj(p)
			if part == nil {
				if s, ok := str(p); ok {
					c.text(role, msg, s)
					continue
				}
				return invalid("content parts must be objects")
			}
			kind := stringOr(part["type"])
			switch kind {
			case "text", "input_text", "output_text", "refusal":
				c.text(role, msg, firstString(part["text"], part["refusal"]))
			case "image_url":
				u := part["image_url"]
				if s, ok := str(u); ok {
					if err := c.imageURL(role, msg, s); err != nil {
						return err
					}
				} else if s, ok := str(obj(u)["url"]); ok {
					if err := c.imageURL(role, msg, s); err != nil {
						return err
					}
				} else {
					return invalid("image_url part has no url")
				}
			case "input_audio", "file", "input_file", "audio":
				if c.roleAllowed(role) {
					c.unsupported("%s content cannot be moderated", kind)
				}
			default:
				c.genericPart(role, msg, part, kind)
			}
		}
		return nil
	default:
		return invalid("message content must be a string or array")
	}
}

// ---------------- OpenAI responses ----------------

func (c *collector) responses(root map[string]any) error {
	if s, ok := str(root["instructions"]); ok {
		c.text("system", -1, s)
	}
	if id, ok := str(root["previous_response_id"]); ok && id != "" {
		c.note("previous_response_id history is stored upstream and was not moderated")
	}
	if root["conversation"] != nil {
		c.note("conversation history is stored upstream and was not moderated")
	}
	switch in := root["input"].(type) {
	case nil:
		if root["prompt"] == nil {
			c.unsupported("request has no input")
		} else {
			c.unsupported("stored prompt templates cannot be moderated")
		}
	case string:
		c.text("user", c.nextMsg(), in)
	case []any:
		for _, it := range in {
			item := obj(it)
			if item == nil {
				if s, ok := str(it); ok {
					c.text("user", c.nextMsg(), s)
					continue
				}
				return invalid("input items must be objects")
			}
			if err := c.responseItem(item); err != nil {
				return err
			}
		}
	default:
		return invalid("input must be a string or array")
	}
	return nil
}

func (c *collector) responseItem(item map[string]any) error {
	kind := stringOr(item["type"])
	if _, hasRole := item["role"]; hasRole || kind == "message" {
		role := normalizeRole(stringOr(item["role"]))
		msg := -1
		if role != "system" {
			msg = c.nextMsg()
		}
		return c.responseContent(role, msg, item["content"])
	}
	msg := c.nextMsg()
	switch {
	case kind == "item_reference":
		c.unsupported("item_reference inputs are stored upstream and cannot be moderated")
	case kind == "reasoning":
		for _, s := range arr(item["summary"]) {
			c.text("assistant", msg, stringOr(obj(s)["text"]))
		}
	case strings.HasSuffix(kind, "_output"):
		return c.responseContent("tool", msg, item["output"])
	case strings.HasSuffix(kind, "_call"):
		c.text("assistant", msg, firstString(item["arguments"], item["input"]))
		if a := obj(item["action"]); a != nil {
			c.text("assistant", msg, compactJSON(a))
		}
	default:
		c.genericPart("user", msg, item, kind)
	}
	return nil
}

func (c *collector) responseContent(role string, msg int, content any) error {
	switch v := content.(type) {
	case nil:
		return nil
	case string:
		c.text(role, msg, v)
		return nil
	case []any:
		for _, p := range v {
			part := obj(p)
			if part == nil {
				return invalid("content parts must be objects")
			}
			kind := stringOr(part["type"])
			switch kind {
			case "input_text", "output_text", "text", "summary_text", "refusal":
				c.text(role, msg, firstString(part["text"], part["refusal"]))
			case "input_image":
				if s, ok := str(part["image_url"]); ok && s != "" {
					if err := c.imageURL(role, msg, s); err != nil {
						return err
					}
				} else if s, ok := str(obj(part["image_url"])["url"]); ok {
					if err := c.imageURL(role, msg, s); err != nil {
						return err
					}
				} else if c.roleAllowed(role) {
					c.unsupported("input_image without an inline or URL image cannot be moderated")
				}
			case "input_file", "input_audio":
				if c.roleAllowed(role) {
					c.unsupported("%s content cannot be moderated", kind)
				}
			default:
				c.genericPart(role, msg, part, kind)
			}
		}
		return nil
	default:
		return invalid("content must be a string or array")
	}
}

// ---------------- Claude messages ----------------

func (c *collector) claude(root map[string]any) error {
	switch s := root["system"].(type) {
	case nil:
	case string:
		c.text("system", -1, s)
	case []any:
		for _, b := range s {
			c.text("system", -1, stringOr(obj(b)["text"]))
		}
	default:
		return invalid("system must be a string or array")
	}
	list, ok := root["messages"].([]any)
	if !ok {
		return invalid("messages must be an array")
	}
	for _, it := range list {
		m := obj(it)
		if m == nil {
			return invalid("each message must be an object")
		}
		role := normalizeRole(stringOr(m["role"]))
		msg := c.nextMsg()
		if err := c.claudeContent(role, msg, m["content"]); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) claudeContent(role string, msg int, content any) error {
	switch v := content.(type) {
	case nil:
		return nil
	case string:
		c.text(role, msg, v)
		return nil
	case []any:
		for _, b := range v {
			block := obj(b)
			if block == nil {
				return invalid("content blocks must be objects")
			}
			kind := stringOr(block["type"])
			switch kind {
			case "text":
				c.text(role, msg, stringOr(block["text"]))
			case "image":
				if err := c.claudeImage(role, msg, obj(block["source"])); err != nil {
					return err
				}
			case "tool_use", "server_tool_use":
				c.text("assistant", msg, compactJSON(block["input"]))
			case "tool_result", "web_search_tool_result":
				if err := c.claudeContent("tool", msg, block["content"]); err != nil {
					return err
				}
			case "thinking":
				c.text("assistant", msg, stringOr(block["thinking"]))
			case "redacted_thinking":
				// Opaque, model-produced; nothing to moderate.
			case "document":
				if c.roleAllowed(role) {
					src := obj(block["source"])
					if stringOr(src["type"]) == "text" {
						c.text(role, msg, stringOr(src["data"]))
					} else {
						c.unsupported("document content cannot be moderated")
					}
				}
			case "search_result":
				if err := c.claudeContent("tool", msg, block["content"]); err != nil {
					return err
				}
			default:
				c.genericPart(role, msg, block, kind)
			}
		}
		return nil
	default:
		return invalid("message content must be a string or array")
	}
}

func (c *collector) claudeImage(role string, msg int, src map[string]any) error {
	if src == nil {
		return invalid("image block has no source")
	}
	switch stringOr(src["type"]) {
	case "base64":
		data, err := decodeBase64(stringOr(src["data"]))
		if err != nil {
			return invalid("image block contains invalid base64")
		}
		return c.imageBytes(role, msg, stringOr(src["media_type"]), data)
	case "url":
		return c.imageURL(role, msg, stringOr(src["url"]))
	default:
		if c.roleAllowed(role) {
			c.unsupported("image source type %q cannot be moderated", stringOr(src["type"]))
		}
		return nil
	}
}

// ---------------- Gemini ----------------

func (c *collector) gemini(root map[string]any) error {
	sys := obj(root["systemInstruction"])
	if sys == nil {
		sys = obj(root["system_instruction"])
	}
	if sys != nil {
		if err := c.geminiParts("system", -1, arr(sys["parts"])); err != nil {
			return err
		}
	}
	contents, ok := root["contents"].([]any)
	if !ok {
		if root["contents"] == nil {
			c.unsupported("request has no contents")
			return nil
		}
		return invalid("contents must be an array")
	}
	for _, it := range contents {
		m := obj(it)
		if m == nil {
			return invalid("each content must be an object")
		}
		role := normalizeRole(stringOr(m["role"]))
		if err := c.geminiParts(role, c.nextMsg(), arr(m["parts"])); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) geminiParts(role string, msg int, parts []any) error {
	for _, p := range parts {
		part := obj(p)
		if part == nil {
			return invalid("parts must be objects")
		}
		if b, _ := part["thought"].(bool); b {
			c.text("assistant", msg, stringOr(part["text"]))
			continue
		}
		switch {
		case part["text"] != nil:
			c.text(role, msg, stringOr(part["text"]))
		case part["inlineData"] != nil || part["inline_data"] != nil:
			d := obj(part["inlineData"])
			if d == nil {
				d = obj(part["inline_data"])
			}
			data, err := decodeBase64(stringOr(d["data"]))
			if err != nil {
				return invalid("inlineData contains invalid base64")
			}
			mt := firstString(d["mimeType"], d["mime_type"])
			if strings.HasPrefix(mt, "image/") {
				if err := c.imageBytes(role, msg, mt, data); err != nil {
					return err
				}
			} else if c.roleAllowed(role) {
				c.unsupported("inline %s data cannot be moderated", mt)
			}
		case part["functionCall"] != nil:
			c.text("assistant", msg, compactJSON(obj(part["functionCall"])["args"]))
		case part["functionResponse"] != nil:
			c.text("tool", msg, compactJSON(obj(part["functionResponse"])["response"]))
		case part["fileData"] != nil || part["file_data"] != nil:
			if c.roleAllowed(role) {
				c.unsupported("fileData references cannot be moderated")
			}
		default:
			c.genericPart(role, msg, part, "gemini-part")
		}
	}
	return nil
}

func stringOr(v any) string {
	s, _ := v.(string)
	return s
}

func firstString(vals ...any) string {
	for _, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
		if v != nil {
			if _, isStr := v.(string); !isStr {
				return compactJSON(v)
			}
		}
	}
	return ""
}
