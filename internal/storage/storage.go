// Package storage reasons about object-store exposure: public reads, public
// writes, and encryption posture derived from configured flags and any
// attached policy document.
package storage

import (
	"strings"

	"github.com/QYVORA/qyvora-imhotep/internal/cloud"
	"github.com/QYVORA/qyvora-imhotep/internal/iam"
)

// Exposure summarizes the risk-relevant posture of one bucket.
type Exposure struct {
	PublicRead  bool
	PublicWrite bool
	Encrypted   bool
	Reasons     []string
}

// AnalyzeBucket combines explicitly configured flags with the bucket policy.
// A bucket is considered public when either its ACL flags say so or its policy
// grants unauthenticated access on read/write actions. Only statements whose
// principal is provably anonymous ("*", "*"/"*", AWS:"*", or no principal)
// count as public; account- or service-scoped policies never do.
func AnalyzeBucket(b *cloud.Bucket) Exposure {
	e := Exposure{Encrypted: b.Encrypted}
	if b.PublicRead {
		e.PublicRead = true
		e.Reasons = append(e.Reasons, "bucket configured public-read")
	}
	if b.PublicWrite {
		e.PublicWrite = true
		e.Reasons = append(e.Reasons, "bucket configured public-write")
	}
	if len(b.Policy) > 0 {
		p, err := iam.ParsePolicy(string(b.Policy))
		if err != nil {
			e.Reasons = append(e.Reasons, "bucket policy unparseable: "+err.Error())
			return e
		}
		for _, st := range p.Statements {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			if !st.Anonymous && st.Principal != "" {
				continue
			}
			if !resourcePublicEligible(st.Resources, b.Name) {
				continue
			}
			for _, a := range st.Actions {
				switch actionExposure(a) {
				case exposureRead:
					if !e.PublicRead {
						e.PublicRead = true
						e.Reasons = append(e.Reasons, "policy grants public read on "+a)
					}
				case exposureWrite:
					if !e.PublicWrite {
						e.PublicWrite = true
						e.Reasons = append(e.Reasons, "policy grants public write on "+a)
					}
				case exposureBoth:
					if !e.PublicRead {
						e.PublicRead = true
						e.Reasons = append(e.Reasons, "policy grants public read on "+a)
					}
					if !e.PublicWrite {
						e.PublicWrite = true
						e.Reasons = append(e.Reasons, "policy grants public write on "+a)
					}
				}
			}
		}
	}
	return e
}

type actionExposureKind int

const (
	exposureNone actionExposureKind = iota
	exposureRead
	exposureWrite
	exposureBoth
)

// actionExposure classifies an IAM action by the side of object-store exposure
// it opens. Service-wide wildcards ("*", "s3:*") affect both reads and writes;
// named actions are matched literally, globally, or through * globs.
func actionExposure(action string) actionExposureKind {
	a := strings.TrimSpace(action)
	if a == "*" || strings.HasSuffix(a, ":*") {
		return exposureBoth
	}
	for _, read := range []string{"GetObject", "ListBucket", "ListAllMyBuckets", "GetBucketList", "Read"} {
		if exactOrGlob(a, read) || exactOrGlob(a, "s3:"+read) {
			return exposureRead
		}
	}
	for _, write := range []string{"PutObject", "DeleteObject", "AbortMultipartUpload", "CreateBucket", "DeleteBucket", "Write"} {
		if exactOrGlob(a, write) || exactOrGlob(a, "s3:"+write) {
			return exposureWrite
		}
	}
	lower := strings.ToLower(a)
	if strings.Contains(lower, "get") || strings.Contains(lower, "read") || strings.Contains(lower, "list") {
		return exposureRead
	}
	if strings.Contains(lower, "put") || strings.Contains(lower, "delete") || strings.Contains(lower, "create") {
		return exposureWrite
	}
	return exposureNone
}

// exactOrGlob matches an action name exactly or against a trailing-glob
// pattern such as "GetObject*".
func exactOrGlob(action, name string) bool {
	if action == name {
		return true
	}
	if strings.Contains(action, "*") {
		return glob(action, name)
	}
	return false
}

// glob matches pattern with '*' (any run) and '?' (any one char).
func glob(pattern, s string) bool {
	var starIdx, starMatch = -1, 0
	i, j := 0, 0
	for i < len(s) {
		if j < len(pattern) && (pattern[j] == '?' || pattern[j] == s[i]) {
			i++
			j++
			continue
		}
		if j < len(pattern) && pattern[j] == '*' {
			starIdx = j
			starMatch = i
			j++
			continue
		}
		if starIdx != -1 {
			starMatch++
			i = starMatch
			j = starIdx + 1
			continue
		}
		return false
	}
	for j < len(pattern) && pattern[j] == '*' {
		j++
	}
	return j == len(pattern)
}

// resourcePublicEligible reports whether a policy resource scope makes the
// statement meaningful for the bucket (wildcard "*", the bucket ARN, or its
// "/*" object scope). An unspecified resource defaults to everything.
func resourcePublicEligible(resources []string, name string) bool {
	if len(resources) == 0 {
		return true
	}
	for _, r := range resources {
		r = strings.TrimSpace(r)
		if r == "*" || strings.HasSuffix(r, "/*") {
			return true
		}
		if strings.Contains(r, ":::") && strings.HasSuffix(r, ":"+name) {
			return true
		}
		if strings.Contains(r, "arn:aws:s3") && strings.Contains(r, name) {
			return true
		}
	}
	return false
}
