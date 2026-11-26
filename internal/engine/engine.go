// Package engine turns one intercepted request into a moderation decision:
// policy match -> extraction -> local wordlists -> moderation API.
package engine

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sort"
	"time"

	"cpa-moderation/internal/extract"
	"cpa-moderation/internal/moderation"
	"cpa-moderation/internal/policy"
	"cpa-moderation/internal/rules"
)

type Moderator interface {
	Moderate(ctx context.Context, items []moderation.Item) (moderation.Verdict, error)
}

type Outcome string

const (
	OutcomeSkip  Outcome = "skip"  // no rule matched; not moderated
	OutcomeAllow Outcome = "allow" // moderated and allowed
	OutcomeBlock Outcome = "block" // content policy violation
	OutcomeError Outcome = "error" // refused because it could not be moderated
)

const (
	CodeViolation   = "content_policy_violation"
	CodeInvalid     = "moderation_input_invalid"
	CodeTooLarge    = "moderation_input_too_large"
	CodeUnavailable = "moderation_unavailable"
	CodeRateLimited = "moderation_rate_limited"
)

type Request struct {
	Scope          string
	Model          string
	RequestedModel string
	Format         string
	ContentType    string
	Body           []byte
}

// Decision never carries request content, matched words or scores.
type Decision struct {
	Outcome          Outcome
	Status           int
	Code             string
	Rules            []string
	Reason           string
	Categories       []string
	LoggedCategories []string
	// Scores holds the highest category scores seen (>= 0.01, rounded). They are
	// operator diagnostics for tuning thresholds and never reach the client.
	Scores    map[string]float64
	Texts     int
	Images    int
	CacheHits int
	Calls     int
	Notes     []string
	Detail    string // operator-facing error detail, content-free
	Duration  time.Duration
}

type Engine struct {
	Snapshot     *policy.Snapshot
	Matcher      *rules.Matcher
	Moderator    Moderator
	Limits       extract.Limits
	RemoteImages string
}

func (e *Engine) Evaluate(ctx context.Context, req Request) Decision {
	start := time.Now()
	d := e.evaluate(ctx, req)
	d.Duration = time.Since(start)
	return d
}

func (e *Engine) evaluate(ctx context.Context, req Request) Decision {
	format := extract.NormalizeFormat(req.Format)
	eff := e.Snapshot.Match(req.Scope, []string{req.RequestedModel, req.Model}, format)
	if eff == nil {
		return Decision{Outcome: OutcomeSkip}
	}
	d := Decision{Rules: eff.RuleIDs}

	content, err := extract.Extract(req.Format, req.ContentType, req.Body, extract.Options{
		Roles:        eff.Roles,
		HistoryLastN: eff.HistoryLastN,
		RemoteImages: e.RemoteImages,
		Limits:       e.Limits,
	})
	if err != nil {
		var xe *extract.Error
		if errors.As(err, &xe) && xe.Kind == extract.KindTooLarge {
			return refuse(d, OutcomeError, http.StatusRequestEntityTooLarge, CodeTooLarge, "input_too_large", xe.Msg)
		}
		return refuse(d, OutcomeError, http.StatusBadRequest, CodeInvalid, "input_invalid", err.Error())
	}
	d.Notes = content.Notes
	d.Texts = len(content.Texts)
	d.Images = len(content.Images)
	if len(content.Unsupported) > 0 {
		if eff.DenyUnsupported {
			return refuse(d, OutcomeError, http.StatusBadRequest, CodeInvalid, "unsupported_content", content.Unsupported[0])
		}
		d.Notes = append(d.Notes, content.Unsupported...)
	}

	if len(eff.Wordlists) > 0 {
		allowed := make(map[string]bool, len(eff.Wordlists))
		for _, w := range eff.Wordlists {
			allowed[w.ID] = true
		}
		for _, seg := range content.Texts {
			if hit, ok := e.Matcher.Match(seg.Text, allowed); ok {
				return refuse(d, OutcomeBlock, http.StatusForbidden, CodeViolation, "wordlist:"+hit.RuleRef(), "")
			}
		}
	}

	var items []moderation.Item
	if eff.CheckText {
		for _, seg := range content.Texts {
			items = append(items, moderation.Item{Text: seg.Text, Cacheable: true})
		}
	}
	if eff.CheckImage {
		for _, im := range content.Images {
			items = append(items, moderation.Item{Image: true, URL: im.URL, Digest: im.Digest, Cacheable: !im.Remote})
		}
	}
	if len(items) == 0 {
		d.Outcome = OutcomeAllow
		d.Reason = "nothing_to_moderate"
		return d
	}

	v, err := e.Moderator.Moderate(ctx, items)
	d.CacheHits, d.Calls = v.CacheHits, v.Calls
	d.Scores = topScores(v.Scores)
	if err != nil {
		if !eff.DenyOnError {
			d.Outcome = OutcomeAllow
			d.Reason = "provider_error_allowed"
			d.Detail = err.Error()
			return d
		}
		if errors.Is(err, moderation.ErrBusy) {
			return refuse(d, OutcomeError, http.StatusTooManyRequests, CodeRateLimited, "local_busy", err.Error())
		}
		return refuse(d, OutcomeError, http.StatusServiceUnavailable, CodeUnavailable, "provider_unavailable", err.Error())
	}
	if v.Flagged {
		var blocking, logged []string
		for _, c := range v.Categories {
			if eff.LogOnly[c] {
				logged = append(logged, c)
			} else {
				blocking = append(blocking, c)
			}
		}
		sort.Strings(blocking)
		sort.Strings(logged)
		d.LoggedCategories = logged
		if len(blocking) > 0 {
			d.Categories = blocking
			return refuse(d, OutcomeBlock, http.StatusForbidden, CodeViolation, "moderation_flagged", "")
		}
	}
	// Stricter per-rule thresholds: block on high scores the API did not flag.
	var over []string
	for cat, th := range eff.Thresholds {
		if v.Scores[cat] >= th {
			over = append(over, cat)
		}
	}
	if len(over) > 0 {
		sort.Strings(over)
		d.Categories = over
		return refuse(d, OutcomeBlock, http.StatusForbidden, CodeViolation, "score_threshold", "")
	}
	d.Outcome = OutcomeAllow
	return d
}

func topScores(in map[string]float64) map[string]float64 {
	if len(in) == 0 {
		return nil
	}
	out := map[string]float64{}
	for k, v := range in {
		if v >= 0.01 {
			out[k] = math.Round(v*1000) / 1000
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func refuse(d Decision, o Outcome, status int, code, reason, detail string) Decision {
	d.Outcome, d.Status, d.Code, d.Reason, d.Detail = o, status, code, reason, detail
	return d
}
