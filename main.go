package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

var typeIntToNames = map[protowire.Type]string{
	0: "Varint",
	5: "Fixed32",
	1: "Fixed64",
	2: "Bytes",
	3: "StartGroup",
	4: "EndGroup",
}

// decodeInput attempts to decode the input string as base64 or hex.
func decodeInput(s string) ([]byte, error) {
	// Try base64 first
	data, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return data, nil
	}
	// Try hex if base64 fails
	data, err = hex.DecodeString(s)
	if err == nil {
		return data, nil
	}
	return nil, fmt.Errorf("failed to decode input as base64 or hex")
}

// Field represents a decoded Protobuf field with its tag, wire type, and value.
type Field struct {
	Tag   protowire.Number
	Type  protowire.Type
	Value interface{}
}

// parseMessage recursively parses Protobuf wire format data into Fields.
func parseMessage(data []byte) ([]Field, int, error) {
	var fields []Field
	remaining := data
	totalConsumed := 0

	for len(remaining) > 0 {
		// Parse tag and wire type
		tagNum, wireType, n := protowire.ConsumeTag(remaining)
		if n < 0 {
			return nil, totalConsumed, fmt.Errorf("invalid tag at offset %d", len(data)-len(remaining))
		}
		remaining = remaining[n:]
		totalConsumed += n

		var value interface{}
		consumed := 0

		// Parse value based on wire type
		switch wireType {
		case protowire.VarintType:
			v, cn := protowire.ConsumeVarint(remaining)
			if cn < 0 {
				return nil, totalConsumed, fmt.Errorf("invalid varint at offset %d", len(data)-len(remaining))
			}
			value = v
			consumed = cn

		case protowire.Fixed32Type:
			v, cn := protowire.ConsumeFixed32(remaining)
			if cn < 0 {
				return nil, totalConsumed, fmt.Errorf("invalid fixed32 at offset %d", len(data)-len(remaining))
			}
			value = v
			consumed = cn

		case protowire.Fixed64Type:
			v, cn := protowire.ConsumeFixed64(remaining)
			if cn < 0 {
				return nil, totalConsumed, fmt.Errorf("invalid fixed64 at offset %d", len(data)-len(remaining))
			}
			value = v
			consumed = cn

		case protowire.BytesType:
			v, cn := protowire.ConsumeBytes(remaining)
			if cn < 0 {
				return nil, totalConsumed, fmt.Errorf("invalid bytes at offset %d", len(data)-len(remaining))
			}

			// Attempt to parse as nested message
			if subFields, subConsumed, err := parseMessage(v); err == nil && subConsumed == len(v) {
				value = subFields
			} else {
				// Fallback to string or bytes
				if utf8.Valid(v) {
					value = string(v)
				} else {
					value = v
				}
			}
			consumed = cn

		default:
			return nil, totalConsumed, fmt.Errorf("unsupported wire type %d at offset %d", wireType, len(data)-len(remaining))
		}

		remaining = remaining[consumed:]
		totalConsumed += consumed
		fields = append(fields, Field{
			Tag:   tagNum,
			Type:  wireType,
			Value: value,
		})
	}

	return fields, totalConsumed, nil
}

// formatFields recursively formats decoded fields into a human-readable string.
func formatFields(fields []Field, indent string) string {
	var builder strings.Builder
	for _, field := range fields {
		builder.WriteString(fmt.Sprintf("%sTag %d (%s): ", indent, field.Tag, typeIntToNames[field.Type]))

		switch v := field.Value.(type) {
		case uint32:
			builder.WriteString(fmt.Sprintf("uint32: %d (0x%x)\n", v, v))
		case uint64:
			builder.WriteString(fmt.Sprintf("uint64: %d (0x%x)\n", v, v))
		case string:
			builder.WriteString(fmt.Sprintf("string: %q\n", v))
		case []byte:
			builder.WriteString(fmt.Sprintf("[]byte: %x (raw bytes)\n", v))
		case []Field:
			builder.WriteString("Message {\n")
			builder.WriteString(formatFields(v, indent+"  "))
			builder.WriteString(fmt.Sprintf("%s}\n", indent))
		default:
			builder.WriteString(fmt.Sprintf("Unknown type: %T\n", v))
		}
	}
	return builder.String()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <encoded_string>")
		os.Exit(1)
	}

	input := os.Args[1]
	msgBytes, err := decodeInput(input)
	if err != nil {
		fmt.Printf("Error decoding input: %v\n", err)
		os.Exit(1)
	}

	// Parse the Protobuf message
	fields, _, err := parseMessage(msgBytes)
	if err != nil {
		panic(fmt.Sprintf("Parse error: %v", err))
	}

	// Print the decoded fields
	fmt.Println("Decoded Protobuf Message:")
	fmt.Print(formatFields(fields, ""))
}
