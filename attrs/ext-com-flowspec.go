package attrs

import (
	"bytes"
	"math"
	"strconv"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/json"
)

type ExtcomFlowRate struct {
	Id   uint16
	Rate float32
}

func NewExtcomFlowRate(et ExtcomType) ExtcomValue {
	return &ExtcomFlowRate{}
}

func (e *ExtcomFlowRate) Unmarshal(raw uint64) error {
	e.Id = uint16(raw >> 32)
	e.Rate = math.Float32frombits(uint32(raw))
	return nil
}

func (e *ExtcomFlowRate) Marshal(cps caps.Caps) uint64 {
	var raw uint64
	raw |= uint64(e.Id) << 32
	raw |= uint64(math.Float32bits(e.Rate))
	return raw
}

func (e *ExtcomFlowRate) ToJSON(dst []byte) []byte {
	if e.Id != 0 {
		dst = append(dst, '"')
		dst = strconv.AppendUint(dst, uint64(e.Id), 10)
		dst = append(dst, ':')
	}
	dst = strconv.AppendFloat(dst, float64(e.Rate), 'f', -1, 32)
	if e.Id != 0 {
		dst = append(dst, '"')
	}
	return dst
}

func (e *ExtcomFlowRate) FromJSON(src []byte) error {
	d := bytes.Split(json.Q(src), []byte(":"))
	if len(d) == 2 {
		v, err := strconv.ParseUint(json.S(d[0]), 10, 16)
		if err != nil {
			return err
		}
		e.Id = uint16(v)
		d = d[1:]
	} else if len(d) != 1 {
		return ErrValue
	}

	v, err := strconv.ParseFloat(json.S(d[0]), 32)
	if err != nil {
		return err
	}
	e.Rate = float32(v)

	return nil
}

type ExtcomFlowAction struct {
	Terminal bool // if set, keep collecting rules and apply all that match
	Sample   bool // if set, enable sampling and logging
}

const (
	EXTCOM_FLOW_ACTION_TERMINAL = 0b00000001
	EXTCOM_FLOW_ACTION_SAMPLE   = 0b00000010
)

func NewExtcomFlowAction(et ExtcomType) ExtcomValue {
	return &ExtcomFlowAction{}
}

func (e *ExtcomFlowAction) Unmarshal(raw uint64) error {
	e.Terminal = raw&EXTCOM_FLOW_ACTION_TERMINAL != 0
	e.Sample = raw&EXTCOM_FLOW_ACTION_SAMPLE != 0
	return nil
}

func (e *ExtcomFlowAction) Marshal(cps caps.Caps) uint64 {
	var raw uint64
	if e.Terminal {
		raw |= EXTCOM_FLOW_ACTION_TERMINAL
	}
	if e.Sample {
		raw |= EXTCOM_FLOW_ACTION_SAMPLE
	}
	return raw
}

func (e *ExtcomFlowAction) ToJSON(dst []byte) []byte {
	dst = append(dst, `{"terminal":`...)
	dst = json.Bool(dst, e.Terminal)
	dst = append(dst, `,"sample":`...)
	dst = json.Bool(dst, e.Sample)
	dst = append(dst, '}')
	return dst
}

func (e *ExtcomFlowAction) FromJSON(src []byte) error {
	e.Terminal = json.GetBool(src, "terminal")
	e.Sample = json.GetBool(src, "sample")
	return nil
}

type ExtcomFlowRedirectNH struct {
	Copy bool
}

func NewExtcomFlowRedirectNH(et ExtcomType) ExtcomValue {
	return &ExtcomFlowRedirectNH{}
}

func (e *ExtcomFlowRedirectNH) Unmarshal(raw uint64) error {
	e.Copy = raw&0x01 != 0
	return nil
}

func (e *ExtcomFlowRedirectNH) Marshal(cps caps.Caps) uint64 {
	var raw uint64
	if e.Copy {
		raw |= 0x01
	}
	return raw
}

func (e *ExtcomFlowRedirectNH) ToJSON(dst []byte) []byte {
	dst = append(dst, `{"copy":`...)
	dst = json.Bool(dst, e.Copy)
	dst = append(dst, '}')
	return dst
}

func (e *ExtcomFlowRedirectNH) FromJSON(src []byte) error {
	e.Copy = json.GetBool(src, "copy")
	return nil
}

type ExtcomFlowDSCP struct {
	DSCP uint8
}

func NewExtcomFlowDSCP(et ExtcomType) ExtcomValue {
	return &ExtcomFlowDSCP{}
}

func (e *ExtcomFlowDSCP) Unmarshal(raw uint64) error {
	e.DSCP = uint8(raw & 0b00111111)
	return nil
}

func (e *ExtcomFlowDSCP) Marshal(cps caps.Caps) uint64 {
	var raw uint64
	raw |= uint64(e.DSCP & 0b00111111)
	return raw
}

func (e *ExtcomFlowDSCP) ToJSON(dst []byte) []byte {
	dst = strconv.AppendUint(dst, uint64(e.DSCP), 10)
	return dst
}

func (e *ExtcomFlowDSCP) FromJSON(src []byte) error {
	v, err := strconv.ParseUint(json.SQ(src), 0, 6)
	if err == nil {
		e.DSCP = uint8(v)
	}
	return err
}
