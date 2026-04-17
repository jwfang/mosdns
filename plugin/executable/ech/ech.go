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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/forward"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"io"
	"strings"
	"unsafe"
)

const PluginType = "ech"

func init() {
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

type ECH struct {
	fw    *fastforward.Forward
	qname string

	ech []byte
}

func validateECH(bs []byte) error {
	r := bytes.NewReader(bs)

	var rl uint16
	err := binary.Read(r, binary.BigEndian, &rl)
	if err != nil {
		return err
	}

	eh := struct {
		Version uint16
		Length  uint16
	}{0, 0}

	i := uint16(2)
	for i < rl {
		err = binary.Read(r, binary.BigEndian, &eh)
		if err != nil {
			return err
		}

		if eh.Version != 0xfe0d {
			return fmt.Errorf("unsupported ECH version: %#x", eh.Version)
		}

		_, err = r.Seek(int64(eh.Length), io.SeekCurrent)
		if err != nil {
			return err
		}

		i += uint16(unsafe.Sizeof(eh)) + eh.Length
	}

	return nil
}

func resolveECH(fw *fastforward.Forward, qn string) ([]byte, error) {
	m := dns.Msg{}
	m.SetQuestion(qn, dns.TypeHTTPS)

	qc := query_context.NewContext(&m)
	err := fw.Exec(context.Background(), qc)
	if err != nil {
		return nil, err
	}

	r := qc.R()
	if r == nil {
		return nil, fmt.Errorf("resolve ECH failed: nil R()")
	}

	for _, rr := range r.Answer {
		if h, ok := rr.(*dns.HTTPS); ok {
			for _, kv := range h.Value {
				if ec, ok := kv.(*dns.SVCBECHConfig); ok {
					err := validateECH(ec.ECH)
					if err == nil {
						return ec.ECH, nil
					} else {
						return nil, fmt.Errorf("resolve ECH failed: invalid ECHConfigList: %w", err)
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("resolve ECH failed: no ECHConfigList")
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

	return &ECH{fw: fw, qname: qn}, nil
}

func (p *ECH) resolveECH(fw *fastforward.Forward, n string) (string, error) {
	_ = dns.Msg{MsgHdr: dns.MsgHdr{Id: dns.Id(), RecursionDesired: true},
		Question: []dns.Question{dns.Question{Name: n, Qtype: dns.TypeHTTPS, Qclass: dns.ClassINET}}}
	return "", nil
}

func (p *ECH) Exec(_ context.Context, qCtx *query_context.Context) error {
	if qCtx.QQuestion().Qtype != dns.TypeHTTPS {
		return nil
	}

	ech, err := resolveECH(p.fw, p.qname)
	if err != nil {
		return err
	}

	r := qCtx.R()
	if r == nil || r.Rcode != dns.RcodeSuccess {
		return nil
	}

	var ok bool
	var ht *dns.HTTPS
	for _, rr := range r.Answer {
		if ht, ok = rr.(*dns.HTTPS); ok {
			break
		}
	}
	if ht == nil {
		ht = &dns.HTTPS{}
		ht.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET}
		ht.Target = "."
		r.Answer = append(r.Answer, ht)
	}

	var ec *dns.SVCBECHConfig
	for _, kv := range ht.Value {
		if ec, ok = kv.(*dns.SVCBECHConfig); ok {
			break
		}
	}
	if ec == nil {
		ht.Value = append(ht.Value, &dns.SVCBECHConfig{ech})
	}

	return nil
}
