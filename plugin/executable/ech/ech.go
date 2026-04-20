/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package ech

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"strings"
	"sync/atomic"
	"time"
)

const PluginType = "ech"

func init() {
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

type reply struct {
	ttl uint32
	ts  time.Time

	rr  *dns.HTTPS
	ech *dns.SVCBECHConfig
}

type ECH struct {
	l *zap.Logger

	fwTag string

	fw    *fastforward.Forward
	qname string

	ipset        *ip_set.IPSet
	cache        *cache.Cache
	pollInterval time.Duration

	r atomic.Pointer[reply]
}

func QuickSetup(bq sequence.BQ, args string) (any, error) {
	fs := strings.Fields(args)
	if len(fs) != 2 {
		return nil, fmt.Errorf("wrong parameters, usage: ech $forward server_name")
	}

	fwt, qn := fs[0], fs[1]
	fw, ok := bq.M().GetPlugin(fwt).(*fastforward.Forward)
	if !ok {
		return nil, fmt.Errorf("no forward with tag `%s`", fwt)
	}
	qn = dns.Fqdn(qn)

	ct, pi := "test_poll_cache", 500*time.Millisecond
	c, ok := bq.M().GetPlugin(ct).(*cache.Cache)
	if !ok {
		return nil, fmt.Errorf("no cache with tag `%s`", ct)
	}

	ech := &ECH{l: bq.L(), fwTag: fwt, fw: fw, qname: qn, cache: c, pollInterval: pi}
	go ech.backgroundResolve()

	return ech, nil
}

func (p *ECH) backgroundResolve() {
	const (
		FailureRetryInterval = 5 * time.Second
		MinimumRetryInterval = 200 * time.Millisecond
	)
	var nextResolve time.Duration

	for {
		select {
		case s := <-time.After(nextResolve):
			ht, ech, ttl, err := resolveECH(p.fw, p.qname)
			if err != nil {
				nextResolve = FailureRetryInterval
				p.l.Warn(fmt.Sprintf("ech : resolve ECH failed, %v", err),
					zap.String("forward_tag", p.fwTag),
					zap.String("fqdn", p.qname),
					zap.String("next_resolve", nextResolve.String()))
				continue
			}

			p.r.Store(&reply{ttl, time.Now(), ht, ech})

			roundtrip := time.Since(s)
			effectiveTTL := max(time.Duration(ttl)*time.Second-roundtrip/2, 0)
			nextResolve = max(effectiveTTL-3*roundtrip/2, MinimumRetryInterval)

			p.l.Info("ech : update ECHConfigList",
				zap.String("forward_tag", p.fwTag),
				zap.String("fqdn", p.qname),
				zap.String("ech", base64.StdEncoding.EncodeToString(ech.ECH)),
				zap.Uint32("ttl", ttl),
				zap.String("forward_roundtrip", roundtrip.String()),
				zap.String("next_resolve", nextResolve.String()))
		}
	}
}

func (p *ECH) Exec(_ context.Context, qCtx *query_context.Context) error {
	if qCtx.QQuestion().Qtype != dns.TypeHTTPS {
		return nil
	}

	r := qCtx.R()

	// exec(ed) before forward, direct reply
	if r == nil {
		cr := p.r.Load()
		if cr == nil {
			p.l.Warn("ech failed: empty ECHConfigList, configuration or network error",
				zap.String("forward_tag", p.fwTag),
				zap.String("fqdn", p.qname))
			return fmt.Errorf("ech failed: empty ECHConfigList, configuration or network error")
		} else {
			r = &dns.Msg{}
			r.SetReply(qCtx.Q())
			ht := *cr.rr
			ht.Hdr.Name = p.qname
			ht.Hdr.Ttl = uint32(max(time.Duration(cr.ttl)*time.Second-time.Since(cr.ts), 0))
			r.Answer = append(r.Answer, &ht)

			qCtx.SetResponse(r)
			return nil
		}
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil
	}

	var ok bool
	var ht *dns.HTTPS
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeHTTPS {
			ht = rr.(*dns.HTTPS)
			break
		}
	}
	if ht == nil {
		ht = &dns.HTTPS{dns.SVCB{Priority: 1, Target: ".",
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}}}
		r.Answer = append(r.Answer, ht)
	}

	var ec *dns.SVCBECHConfig
	for _, kv := range ht.Value {
		if ec, ok = kv.(*dns.SVCBECHConfig); ok {
			break
		}
	}
	if ec == nil {
		ech := p.r.Load().ech
		if ht == nil {
			p.l.Warn("ech failed: empty ECHConfigList, configuration or network error",
				zap.String("forward_tag", p.fwTag),
				zap.String("fqdn", p.qname))
			return fmt.Errorf("ech failed: empty ECHConfigList, configuration or network error")
		} else {
			ht.Value = append(ht.Value, ech)
		}
	}

	return nil
}
