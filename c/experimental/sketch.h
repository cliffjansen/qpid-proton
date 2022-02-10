// A common pool of buffers to put both encrypted and decrypted bytes in:
// - this could easily just be split into 2 result buffer sets if preferred.

// Give buffers to store encryption/decryption results
// returns the number of buffers taken - it's possible that we don't have space
// to record all of them
size_t pn_tls_give_result_buffers(pn_tls*, pn_raw_buffer_t const*, size_t count);

// Take result buffers back into app ownership, return the actual number of buffers returned
// keep calling these until the number returned is 0 to make sure you get all buffers currently available
size_t pn_tls_decrypted_result(pn_tls*, pn_raw_buffer_t const*, size_t count);
size_t pn_tls_encrypted_result(pn_tls*, pn_raw_buffer_t const*, size_t count);

// Encrypt buffers
// returned value is number of buffers processed - these buffers are implicitly returned to the app
// The others are held by the tls code (hmm up to a max I guess as we're not going to have indefinite
// space for buffer descriptors)
size_t pn_tls_encrypt(pn_tls*, pn_raw_buffer_t const* bufs, size_t count_bufs)

// Decrypt
// returned value is number of buffers processed - these buffers are implicitly returned to the app
// The others are held by the tls code (hmm up to a max I guess as we're not going to have indefinite
// space for buffer descriptors)
size_t pn_tls_decrypt(pn_tls*, pn_raw_buffer_t const* bufs, size_t count_bufs)

// Take input buffers back into app ownership, return the actual number of buffers returned
// keep calling these until the number returned is 0 to make sure you get all buffers currently available
// These names are a bit too close for comfort to the result buffers but they'll do for now
size_t pn_tls_take_decrypt_buffers(pn_tls*, pn_raw_buffer_t const*, size_t count);
size_t pn_tls_take_encrypt_buffers(pn_tls*, pn_raw_buffer_t const*, size_t count);

// Return the max number of buffers we can hold
pn_tls_query_max_encrypt_buffers(pn_tls*);
pn_tls_query_max_decrypt_buffers(pn_tls*);

// Query number of _bytes_ needed to process
// This will be 0 if we have nothing pending to encrypt, 
// Hopefully we can tell a number of bytes necessary to encrypt what's pending
// otherwise we my have to loop calling this and pn_tls_give_result_buffers()

// Possibly this should return a number of buffers needed - it's not clear to me without
// implementing!

// Also possible is that all this can do is return a bool and that would require to loop
// giving buffers until false.
size_t pn_tls_query_need_result_buffers(pn_tls*);


