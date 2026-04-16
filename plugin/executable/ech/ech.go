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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"io"
	"unsafe"
)

const PluginType = "ech"

func init() {
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

type ECH struct {
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

func QuickSetup(_ sequence.BQ, ech string) (any, error) {
	b, e := base64.StdEncoding.DecodeString(ech)
	if e != nil {
		return nil, e
	}
	e = validateECH(b)
	if e != nil {
		return nil, e
	}
	return &ECH{ech: b}, nil
}

func (p *ECH) Exec(_ context.Context, qCtx *query_context.Context) error {
	if qCtx.QQuestion().Qtype != dns.TypeHTTPS {
		return nil
	}

	r := qCtx.R()
	if r == nil || r.Rcode != dns.RcodeSuccess {
		return nil
	}

	for _, rr := range r.Answer {
		if rr.Header().Rrtype != dns.TypeHTTPS {
			continue
		}
		h, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		f := false
		for _, kv := range h.Value {
			if kv.Key() == dns.SVCB_ECHCONFIG {
				f = true
			}
		}
		if !f {
			c := &dns.SVCBECHConfig{ECH: p.ech}
			h.Value = append(h.Value, c)
		}

	}

	return nil
}
