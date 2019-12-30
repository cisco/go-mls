package mls

// struct {
//   // GroupContext inputs
//   opaque group_id<0..255>;
//   uint32 epoch;
//   optional<RatchetNode> tree<1..2^32-1>;
//   opaque confirmed_transcript_hash<0..255>;
//
//   // Inputs to the next round of the key schedule
//   opaque interim_transcript_hash<0..255>;
//   opaque epoch_secret<0..255>;
//
//   uint32 signer_index;
//   opaque signature<0..255>;
// } GroupInfo;
type GroupInfo struct {
	GroupId                      []byte `tls:"head=1"`
	Epoch                        Epoch
	TreeHash                     []byte `tls:"head=1"`
	Tree                         *RatchetTree
	PriorConfirmedTranscriptHash []byte `tls:"head=1"`
	ConfirmedTranscriptHash      []byte `tls:"head=1"`
	InterimTranscriptHash        []byte `tls:"head=1"`
	Path                         *DirectPath
	Confirmation                 []byte `tls:"head=1"`
	SignerIndex                  uint32
	Signature                    []byte `tls:"head=2"`
}

//  struct {
//    opaque init_secret<1..255>;
//  } KeyPackage;
type KeyPackage struct {
	InitSecret []byte `tls:"head=1"`
}

// struct {
//   opaque client_init_key_hash<1..255>;
//   HPKECiphertext encrypted_key_package;
// } EncryptedKeyPackage;
type EncryptedKeyPackage struct {
	ClientInitKeyHash []byte `tls:"head=1"`
	EncryptedPackage  HPKECiphertext
}

// struct {
//   ProtocolVersion version = mls10;
//   CipherSuite cipher_suite;
//   EncryptedKeyPackage key_packages<1..2^32-1>;
//   opaque encrypted_group_info<1..2^32-1>;
// } Welcome;
type Welcome struct {
	Version             uint8
	CipherSuite         CipherSuite
	EncryptedKeyPackage EncryptedKeyPackage
	EncryptedGroupInfo  []byte `tls:"head=4"`
}
