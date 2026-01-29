package proto

// FrameType: 1-byte type on wire.
type FrameType uint8

const (
	TypeAuthRequest    FrameType = 0x01
	TypeAuthResponse   FrameType = 0x02
	TypePing           FrameType = 0x03
	TypePong           FrameType = 0x04
	TypeRouteRequest   FrameType = 0x05
	TypeRouteResponse  FrameType = 0x06
	TypeData           FrameType = 0x10
	TypePQKey          FrameType = 0x11 // agent sends encapsulation key (ML-KEM-768, 1184 bytes)
	TypePQCiphertext   FrameType = 0x12 // client sends KEM ciphertext so agent can decapsulate
)

// FrameHeader size: 1 + 4 + 4 = 9 bytes (type, stream_id, length).
const FrameHeaderSize = 9

// MaxPayloadSize 16MiB.
const MaxPayloadSize = 1024 * 1024 * 16

// MaxPaddingSize max padding bytes in Data (masking).
const MaxPaddingSize = 255
