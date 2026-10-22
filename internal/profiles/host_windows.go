package profiles

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const MaxFrame = 32 * 1024 * 1024

func readBounded(r io.Reader, limit int) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if e != nil || len(b) > limit {
		return nil, errors.New("Данные превышают допустимый размер.")
	}
	return b, nil
}
func RunHost(ctx context.Context, input io.Reader, output io.Writer, app *Application) error {
	for {
		var header [4]byte
		if _, e := io.ReadFull(input, header[:]); e != nil {
			if e == io.EOF {
				return nil
			}
			return e
		}
		size := binary.LittleEndian.Uint32(header[:])
		if size < 2 || size > MaxFrame {
			return ErrImport
		}
		data := make([]byte, int(size))
		if _, e := io.ReadFull(input, data); e != nil {
			clear(data)
			return e
		}
		var request Request
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		e := error(nil)
		if !boundedJSON(data) {
			e = ErrImport
		} else {
			e = decoder.Decode(&request)
		}
		if e == nil && decoder.Decode(new(any)) != io.EOF {
			e = ErrImport
		}
		clear(data)
		var value any
		if e == nil {
			value, e = app.Handle(ctx, request)
		}
		reply := struct {
			Version int
			Value   any
			Error   *string
		}{Version: 1, Value: value}
		if e != nil {
			message := e.Error()
			reply.Error = &message
		}
		encoded, e := json.Marshal(reply)
		if e != nil {
			return e
		}
		if len(encoded) > MaxFrame {
			clear(encoded)
			return ErrImport
		}
		binary.LittleEndian.PutUint32(header[:], uint32(len(encoded)))
		if _, e = output.Write(header[:]); e == nil {
			_, e = output.Write(encoded)
		}
		clear(encoded)
		if e != nil {
			return e
		}
	}
}
