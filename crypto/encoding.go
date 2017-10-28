package crypto

import (
	"bytes"
	"encoding/binary"
	"reflect"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/share/pedersen/dkg"
	"github.com/dedis/kyber/share/pedersen/vss"
	"github.com/dedis/protobuf"
)

func (p *Point) MarshalBinary() ([]byte, error) {
	return p.p.MarshalBinary()
}

func (p *Point) UnmarshalBinary(data []byte) error {
	p.p = SUITE.Point()
	return p.p.UnmarshalBinary(data)
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.s.MarshalBinary()
}

func (s *Scalar) UnmarshalBinary(data []byte) error {
	s.s = SUITE.Scalar()
	return s.s.UnmarshalBinary(data)
}

func (k *PrivateKey) MarshalBinary() ([]byte, error) {
	return k.s.MarshalBinary()
}

func (k *PrivateKey) UnmarshalBinary(data []byte) error {
	k.s = SUITE.Scalar()
	return k.s.UnmarshalBinary(data)
}

func (k *PublicKey) MarshalBinary() ([]byte, error) {
	return k.p.MarshalBinary()
}

func (k *PublicKey) UnmarshalBinary(data []byte) error {
	k.p = SUITE.Point()
	return k.p.UnmarshalBinary(data)
}

func writeUint32(buf *bytes.Buffer, val uint32) error {
	err := binary.Write(buf, binary.LittleEndian, val)
	if err != nil {
		return err
	}
	return nil
}

func readUint32(buf *bytes.Buffer) (uint32, error) {
	var tmp uint32
	err := binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return 0, err
	}
	return tmp, nil
}

func writeBytes(buf *bytes.Buffer, msg []byte) error {
	err := writeUint32(buf, uint32(len(msg)))
	if err != nil {
		return err
	}
	_, err = buf.Write(msg)
	if err != nil {
		return err
	}
	return nil
}

func readBytes(buf *bytes.Buffer) ([]byte, error) {
	size, err := readUint32(buf)
	res := make([]byte, size)
	_, err = buf.Read(res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (d *ThresholdDeal) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	deal := d.D
	writeUint32(buf, deal.Index)
	b, err := deal.Deal.DHKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	err = writeBytes(buf, b)
	if err != nil {
		return nil, err
	}
	err = writeBytes(buf, deal.Deal.Signature)
	if err != nil {
		return nil, err
	}
	err = writeBytes(buf, deal.Deal.Nonce)
	if err != nil {
		return nil, err
	}
	err = writeBytes(buf, deal.Deal.Cipher)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *ThresholdDeal) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	deal := new(dkg.Deal)
	var err error
	deal.Index, err = readUint32(buf)
	if err != nil {
		return err
	}
	deal.Deal = new(vss.EncryptedDeal)
	deal.Deal.DHKey = SUITE.Point()
	b, err := readBytes(buf)
	if err != nil {
		return err
	}
	err = deal.Deal.DHKey.UnmarshalBinary(b)
	if err != nil {
		return err
	}

	deal.Deal.Signature, err = readBytes(buf)
	if err != nil {
		return err
	}
	deal.Deal.Nonce, err = readBytes(buf)
	if err != nil {
		return err
	}
	deal.Deal.Cipher, err = readBytes(buf)
	d.D = deal
	return err
}

func (r *ThresholdResponse) MarshalBinary() ([]byte, error) {
	buf, err := protobuf.Encode(r.R)
	cp := make([]byte, len(buf))
	copy(cp, buf)
	return cp, err
}

func (r *ThresholdResponse) UnmarshalBinary(data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	r.R = new(dkg.Response)
	constructors := make(protobuf.Constructors)
	var point kyber.Point
	var secret kyber.Scalar
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return SUITE.Point() }
	constructors[reflect.TypeOf(&secret).Elem()] = func() interface{} { return SUITE.Scalar() }
	return protobuf.DecodeWithConstructors(cp, r.R, constructors)
}

func (t *Trap) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint32(t.Gid))
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(t.Nonce)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (t *Trap) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	var tmp uint32
	err := binary.Read(buf, binary.LittleEndian, &tmp)
	if err != nil {
		return err
	}
	t.Gid = int(tmp)

	nonce := make([]byte, NONCE_LEN)
	_, err = buf.Read(nonce)
	if err != nil {
		return err
	}
	t.Nonce = nonce
	return nil
}

func (i *InnerCiphertext) MarshalBinary() ([]byte, error) {
	r, err := i.R.p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(r, i.C...), nil
}

func (i *InnerCiphertext) UnmarshalBinary(data []byte) error {
	R := SUITE.Point()
	err := R.UnmarshalBinary(data[:R.MarshalSize()])
	if err != nil {
		return err
	}
	i.R = &Point{R}
	c := make([]byte, len(data)-R.MarshalSize())
	copy(c, data[R.MarshalSize():])
	i.C = c
	return nil
}
