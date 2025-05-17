package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
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
			value = interpretVarint(v)
			consumed = cn

		case protowire.Fixed32Type:
			v, cn := protowire.ConsumeFixed32(remaining)
			if cn < 0 {
				return nil, totalConsumed, fmt.Errorf("invalid fixed32 at offset %d", len(data)-len(remaining))
			}
			value = interpretFixed32(v)
			consumed = cn

		case protowire.Fixed64Type:
			v, cn := protowire.ConsumeFixed64(remaining)
			if cn < 0 {
				return nil, totalConsumed, fmt.Errorf("invalid fixed64 at offset %d", len(data)-len(remaining))
			}
			value = interpretFixed64(v)
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

// zigZagDecode32 decodes a ZigZag-encoded 32-bit value
func zigZagDecode32(n uint32) int32 {
	return int32(n>>1) ^ -int32(n&1)
}

// zigZagDecode64 decodes a ZigZag-encoded 64-bit value
func zigZagDecode64(n uint64) int64 {
	return int64(n>>1) ^ -int64(n&1)
}

func interpretVarint(v uint64) interface{} {
	// Try different interpretations of the varint
	var interpretations []string

	// Unsigned integers
	interpretations = append(interpretations, fmt.Sprintf("[uint64]: %v", v))
	interpretations = append(interpretations, fmt.Sprintf("[uint32]: %v", uint32(v)))

	// Signed integers
	interpretations = append(interpretations, fmt.Sprintf("[int64]: %v", int64(v)))
	interpretations = append(interpretations, fmt.Sprintf("[int32]: %v", int32(v)))
	interpretations = append(interpretations, fmt.Sprintf("[sint64]: %v", zigZagDecode64(v)))
	interpretations = append(interpretations, fmt.Sprintf("[sint32]: %v", zigZagDecode32(uint32(v))))

	// Boolean
	if v == 0 {
		interpretations = append(interpretations, fmt.Sprintf("[bool]: %v", false))
	} else if v == 1 {
		interpretations = append(interpretations, fmt.Sprintf("[bool]: %v", true))
	}

	// Enum
	interpretations = append(interpretations, fmt.Sprintf("[enum]: %v", v))

	return interpretations
}
func interpretFixed32(v uint32) interface{} {
	var interpretations []string
	interpretations = append(interpretations, fmt.Sprintf("[fixed32]: %v", v))
	interpretations = append(interpretations, fmt.Sprintf("[float]: %v", math.Float32frombits(v)))
	interpretations = append(interpretations, fmt.Sprintf("[sfixed32]: %v", int32(v)))
	return interpretations
}

func interpretFixed64(v uint64) interface{} {
	var interpretations []string
	interpretations = append(interpretations, fmt.Sprintf("[fixed64]: %v", v))
	interpretations = append(interpretations, fmt.Sprintf("[double]: %v", math.Float64frombits(v)))
	interpretations = append(interpretations, fmt.Sprintf("[sfixed64]: %v", int64(v)))
	return interpretations
}

// formatFields recursively formats decoded fields into a human-readable string.
func formatFields(fields []Field, indent string) string {
	var builder strings.Builder
	for _, field := range fields {
		builder.WriteString(fmt.Sprintf("%sTag %d (%s): ", indent, field.Tag, typeIntToNames[field.Type]))

		switch v := field.Value.(type) {
		case []string:
			// Multiple interpretations (varint, fixed32/64)
			builder.WriteString("{\n")
			builder.WriteString(fmt.Sprintf("%s  %s\n", indent, strings.Join(v, ", ")))
			builder.WriteString(indent + "}\n")
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

func extractProtobufBytesIfRecognizedAsGrpcWebMsg(data []byte) []byte {
	if len(data) < 5 {
		// Data too short for gRPC-Web frame
		return data
	}

	compressionFlag := data[0]
	if compressionFlag != 0 {
		// Compressed messages are not supported
		return data
	}

	messageLength := binary.BigEndian.Uint32(data[1:5])
	messageStart := 5
	messageEnd := messageStart + int(messageLength)
	if messageEnd > len(data) {
		// Parsed message length exceeds available data; therefore the input can't be gRPC-Web message
		return data
	}
	fmt.Println("The input will be parsed as gRPC-Web message")
	return data[messageStart:messageEnd]
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
	msgBytes = extractProtobufBytesIfRecognizedAsGrpcWebMsg(msgBytes)
	fields, _, err := parseMessage(msgBytes)
	if err != nil {
		panic(fmt.Sprintf("Parse error: %v", err))
	}

	// Print the decoded fields
	fmt.Println("Decoded Protobuf Message:")
	fmt.Print(formatFields(fields, ""))
}
