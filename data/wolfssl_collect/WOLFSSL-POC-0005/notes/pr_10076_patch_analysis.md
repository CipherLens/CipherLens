
## Vulnerable Source Confirmation: wolfSSL v5.9.0-stable

The vulnerable version contains the old Dtls13WriteAckMessage signature:

- Dtls13WriteAckMessage(WOLFSSL* ssl, Dtls13RecordNumber* recordNumberList, word32* length)

The vulnerable helper Dtls13GetAckListLength walks the entire ACK record linked list and stores the computed byte length into a word16 output variable:

- DTLS13_RN_SIZE is 16
- numberElements is unbounded
- length is assigned as (word16)(DTLS13_RN_SIZE * numberElements)

The source contains a TODO comment:

- TODO: check that we don't exceed the maximum length

This confirms the root cause hypothesis:

- ACK record count is unbounded
- ACK encoded length is truncated to word16
- CheckAvailableSize uses the truncated msgSz
- Dtls13WriteAckMessage later writes all ACK records in the linked list
- A sufficiently large ACK record list can overflow the output buffer

Expected vulnerable trigger shape:

- Build a DTLS 1.3 WOLFSSL object with a usable DTLS 1.3 encryption epoch and output buffer
- Add more than DTLS13_ACK_MAX_RECORDS ACK records through Dtls13RtxAddAck
- Call Dtls13WriteAckMessage
- Observe ASan heap-buffer-overflow during ACK record serialization
