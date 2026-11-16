// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package appmessages

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FormType is a decision the holder answers in the wallet: the app composes a
// view from a closed set of components the wallet draws itself, and supplies
// data and the actions on its buttons, never code, markup or button text.
const FormType = "app-form"

// The limits are the form's whole vocabulary. Each is small on purpose: the
// wallet draws everything natively and the holder must be able to read it.
const (
	maxFormBytes  = 3 << 10
	maxTitle      = 80
	maxBlocks     = 12
	maxText       = 600
	maxFields     = 8
	maxFieldLabel = 40
	maxFieldValue = 200
	maxAttrValue  = 200
	maxAttrs      = 12
	maxActions    = 3
)

// actionKinds is the closed list of buttons. The wallet supplies the label and
// the style for each, so an app cannot write a button that says one thing and
// does another.
var actionKinds = map[string]bool{
	"approve": true, "deny": true, "accept": true, "decline": true, "confirm": true,
}

var (
	formIDShape   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	actionIDShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	attrKeyShape  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Form is what the IdP needs to know about a form: its reference, its digest
// and the actions it offers. The rest stays sealed and is the wallet's.
type Form struct {
	ID      string
	Digest  string
	Actions []string
}

// ErrForm wraps every reason a form is refused.
var ErrForm = errors.New("invalid app form")

func formErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrForm, fmt.Sprintf(format, a...))
}

// FormDigest is the hash an answer commits to: SHA-256 of the form string's
// exact bytes, hex. The app computes the same over the string it sent.
func FormDigest(form string) string {
	sum := sha256.Sum256([]byte(form))
	return hex.EncodeToString(sum[:])
}

// ParseFormPayload reads an app-form payload {kind, form} and validates the
// form. Anything the wallet would not draw is refused here, so the app learns
// of it from the status rather than the holder seeing a broken card.
func ParseFormPayload(payload json.RawMessage) (kind string, f Form, err error) {
	var p struct {
		Kind string `json:"kind"`
		Form string `json:"form"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &p) != nil {
		return "", Form{}, formErr("the payload is an object with a kind and a form string")
	}
	if p.Kind != "request" && p.Kind != "invitation" {
		return "", Form{}, formErr("kind must be request or invitation")
	}
	f, err = ValidateForm(p.Form)
	return p.Kind, f, err
}

// ValidateForm checks a form against the component vocabulary.
func ValidateForm(form string) (Form, error) {
	if form == "" || len(form) > maxFormBytes || !utf8.ValidString(form) {
		return Form{}, formErr("the form is a JSON string of at most %d bytes", maxFormBytes)
	}
	var raw struct {
		V        int               `json:"v"`
		ID       string            `json:"id"`
		Title    string            `json:"title"`
		Blocks   []json.RawMessage `json:"blocks"`
		Actions  []struct{ ID, Kind string }
		Callback string `json:"callback"`
		Link     string `json:"link"`
	}
	dec := json.NewDecoder(strings.NewReader(form))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return Form{}, formErr("the form does not parse: %v", err)
	}
	if raw.V != 1 {
		return Form{}, formErr("v must be 1")
	}
	if !formIDShape.MatchString(raw.ID) {
		return Form{}, formErr("id must match [A-Za-z0-9_-]{1,64}")
	}
	if err := checkText("title", raw.Title, maxTitle, false); err != nil || raw.Title == "" {
		return Form{}, formErr("title is required, plain text, at most %d characters", maxTitle)
	}
	if len(raw.Blocks) > maxBlocks {
		return Form{}, formErr("at most %d blocks", maxBlocks)
	}
	for i, b := range raw.Blocks {
		if err := checkBlock(b); err != nil {
			return Form{}, formErr("block %d: %v", i, err)
		}
	}
	if len(raw.Actions) == 0 || len(raw.Actions) > maxActions {
		return Form{}, formErr("between 1 and %d actions", maxActions)
	}
	ids := make([]string, 0, len(raw.Actions))
	seenID, seenKind := map[string]bool{}, map[string]bool{}
	for _, a := range raw.Actions {
		if !actionIDShape.MatchString(a.ID) || seenID[a.ID] {
			return Form{}, formErr("action ids are unique slugs")
		}
		if !actionKinds[a.Kind] || seenKind[a.Kind] {
			return Form{}, formErr("action kind %q is not on the list, or repeats", a.Kind)
		}
		seenID[a.ID], seenKind[a.Kind] = true, true
		ids = append(ids, a.ID)
	}
	if !safePath(raw.Callback) {
		return Form{}, formErr("callback must be a path on the app's host")
	}
	if raw.Link != "" && !safePath(raw.Link) {
		return Form{}, formErr("link must be a path on the app's host")
	}
	return Form{ID: raw.ID, Digest: FormDigest(form), Actions: ids}, nil
}

func checkBlock(b json.RawMessage) error {
	var head struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(b, &head) != nil {
		return errors.New("not an object")
	}
	strict := func(v any) error {
		d := json.NewDecoder(strings.NewReader(string(b)))
		d.DisallowUnknownFields()
		return d.Decode(v)
	}
	switch head.Type {
	case "divider":
		var v struct{ Type string }
		return strict(&v)
	case "text":
		var v struct{ Type, Text string }
		if err := strict(&v); err != nil {
			return err
		}
		if v.Text == "" {
			return errors.New("text is empty")
		}
		return checkText("text", v.Text, maxText, true)
	case "fields":
		var v struct {
			Type  string
			Items []struct{ Label, Value string }
		}
		if err := strict(&v); err != nil {
			return err
		}
		if len(v.Items) == 0 || len(v.Items) > maxFields {
			return fmt.Errorf("between 1 and %d fields", maxFields)
		}
		for _, it := range v.Items {
			if it.Label == "" || it.Value == "" {
				return errors.New("a field needs a label and a value")
			}
			if err := checkText("label", it.Label, maxFieldLabel, false); err != nil {
				return err
			}
			if err := checkText("value", it.Value, maxFieldValue, false); err != nil {
				return err
			}
		}
		return nil
	case "attributes":
		var v struct {
			Type   string
			Values map[string]string
		}
		if err := strict(&v); err != nil {
			return err
		}
		if len(v.Values) == 0 || len(v.Values) > maxAttrs {
			return fmt.Errorf("between 1 and %d attributes", maxAttrs)
		}
		for k, val := range v.Values {
			if !attrKeyShape.MatchString(k) {
				return fmt.Errorf("attribute key %q is not a canonical key", k)
			}
			if err := checkText(k, val, maxAttrValue, false); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown block type %q", head.Type)
	}
}

// checkText refuses what could make app text pass for the wallet's own or
// hide what it says: control characters (a newline only where allowed),
// bidirectional overrides and isolates, and zero-width characters.
func checkText(name, s string, max int, newlines bool) error {
	if utf8.RuneCountInString(s) > max {
		return fmt.Errorf("%s is longer than %d characters", name, max)
	}
	for _, r := range s {
		if r == '\n' && newlines {
			continue
		}
		if unicode.IsControl(r) || isInvisible(r) {
			return fmt.Errorf("%s contains a control or invisible character (U+%04X)", name, r)
		}
	}
	return nil
}

func isInvisible(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F, r == 0x061C:
		return true // bidirectional embeddings, overrides, isolates and marks
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF, r == 0x00AD:
		return true // zero-width and soft hyphen
	}
	return false
}

func safePath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && len(p) <= maxPath &&
		!strings.ContainsAny(p, "\\\r\n\t ")
}

// platformHostShape is where a form's answer may go: an app's own platform
// hostname, one label under the enclave zones. The control plane names it;
// this refuses to record a form against anything else, so neither a mistake
// nor a compromised control plane can point an answer at another host. The
// wallet applies the same rule before it sends.
var platformHostShape = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.apps(\.test)?\.privasys\.org$`)

// ValidPlatformHost reports whether host may receive a form's answer.
func ValidPlatformHost(host string) bool { return platformHostShape.MatchString(host) }
