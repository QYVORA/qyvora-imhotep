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
// grants unauthenticated access on read/write actions.
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
			if st.Principal != "" && !strings.Contains(st.Principal, "*") {
				continue
			}
			for _, a := range st.Actions {
				switch {
				case strings.Contains(a, "GetObject") || strings.Contains(a, "Read"):
					if !e.PublicRead {
						e.PublicRead = true
						e.Reasons = append(e.Reasons, "policy grants public read on "+a)
					}
				case strings.Contains(a, "PutObject") || strings.Contains(a, "Write") || strings.Contains(a, "DeleteObject"):
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
