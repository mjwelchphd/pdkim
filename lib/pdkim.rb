require 'resolv'
require_relative '../ext/pdkim/pdkimglue'

module PDKIM

  CRLF = "\r\n"

  # ctx = pdkim_init_sign(mode, domain, selector, rsa_privkey)
  #
  # Initialize context for signing.
  #
  #    mode
  #      PDKIM_INPUT_NORMAL or PDKIM_INPUT_SMTP. When SMTP
  #      input is used, the lib will deflate double-dots at
  #      the start of atline to a single dot, and it will
  #      stop processing input when a line with and single
  #      dot is received (Excess input will simply be ignored).
  #
  #    domain
  #      The domain to sign as. This value will land in the
  #      d= tag of the signature. For example, if the MAIL FROM
  #      address is joe@mail.example.com, the domain is
  #      example.com.
  #
  #    selector
  #      The selector string to use. This value will land in
  #      the s= tag of the signature. For example, if the DNS DKIM TXT
  #      record contains 2015may._domainkey.example.com, the selector
  #      is 2015may.
  #
  #    rsa_privkey
  #      The private RSA key, in ASCII armor. It MUST NOT be
  #      encrypted.
  #
  # Returns: A freshly allocated ctx (context)
  #
  def pdkim_init_sign(mode, domain, selector, rsa_privkey)
    ruby_pdkim_init_sign(mode, domain, selector, rsa_privkey)
  end

  # ctx = pdkim_init_verify(mode) { |name| ...code to retrieve domain's public key... }
  #
  # Initialize context for verification.
  #
  #    mode
  #      PDKIM_INPUT_NORMAL or PDKIM_INPUT_SMTP. When SMTP
  #      input is used, the lib will deflate double-dots at
  #      the start of atline to a single dot, and it will
  #      stop processing input when a line with and single
  #      dot is received (Excess input will simply be ignored).
  #
  #    block
  #      Tom's pdkim lib does not include a DNS resolver, so one
  #      has been provided in this gem called "pdkim_dkim_public_key_lookup(name)."
  #      You may provide some other mechanism, however. This call, then, would be:
  #
  #      ctx = pdkim_init_verify(mode) do |name|
  #        your_public_key_lookup(name)
  #      end
  #
  #      NOTE: Although the block is on this call to pdkim_init_verify,
  #      the ACTUAL callbacks are made from pdkim_feed_finish as the
  #      DKIM signatures (there can be many) are being validated one by
  #      one. As each signature will have a different domain, a callback
  #      is used to do the lookup.
  #
  # Returns: A freshly allocated ctx (context)
  #
  def pdkim_init_verify(state)
    raise ArgumentError.new("pdkim_init_verify missing block") if !block_given?
    ruby_pdkim_init_verify(state) do |name|
      r = yield(name)
    end
  end

  # pdkim_set_debug_stream(ctx, file_name)
  # pdkim_set_debug_stream(ctx, file_number)
  #
  # Set up debugging stream.
  #
  # When pdkim.c was compiled with DEBUG defined (which is the
  # recommended default), you can set up a stream where it
  # sends debug output to. If you don't set a debug
  # stream, no debug output is generated.
  #    file_name
  #      If the first option is called, a file by the name
  #      file_name is opened, and debugging output is APPENDED to it.
  #      Ex: pdkim_set_debug_stream(ctx, "my_debug_log")
  #
  #    file_number
  #      If the second option is choosen, a file by the number
  #      file_number is opened, and debugging output is APPENDED to it.
  #      Ex: pdkim_set_debug_stream(ctx, 2) # STDERR
  #
  # Returns: nil
  #
  def pdkim_set_debug_stream(ctx, id)
    ruby_pdkim_set_debug_stream(ctx, id)
  end

  # ok = pdkim_set_optional(ctx, sign_headers, identity, canon_headers, \
  #                         canon_body, bodylength, algo, created, expires)
  #
  # OPTIONAL: Set additional optional signing options. If you do
  # not use this function, sensible defaults (see below) are used.
  # Any strings you pass in are dup'ed, so you can safely release
  # your copy even before calling pdkim_free() on your context.
  #
  #    sign_headers (default nil)
  #      Colon-separated list of header names. Headers with
  #      a name matching the list will be included in the
  #      signature. When this is NULL, the list of headers
  #      recommended in RFC4781 will be used.
  #
  #    identity (default nil)
  #      An identity string as described in RFC4781. It will
  #      be put into the i= tag of the signature.
  #
  #    canon_headers (default PDKIM_CANON_SIMPLE)
  #      Canonicalization algorithm to use for headers. One
  #      of PDKIM_CANON_SIMPLE or PDKIM_CANON_RELAXED.
  #
  #    canon_body (default PDKIM_CANON_SIMPLE)
  #      Canonicalization algorithm to use for the body. One
  #      of PDKIM_CANON_SIMPLE or PDKIM_CANON_RELAXED.
  #
  #    bodylength (default -1)
  #      Amount of canonicalized body bytes to include in
  #      the body hash calculation. A value of 0 means that
  #      the body is not included in the signature. A value
  #      of -1 (the default) means that there is no limit.
  #
  #    algo (default PDKIM_ALGO_RSA_SHA256)
  #      One of PDKIM_ALGO_RSA_SHA256 or PDKIM_ALGO_RSA_SHA1.
  #
  #    created (default 0)
  #      Seconds since the epoch, describing when the signature
  #      was created. This is copied to the t= tag of the
  #      signature. Setting a value of 0 (the default) omits
  #      the tag from the signature.
  #
  #    expires (default 0)
  #      Seconds since the epoch, describing when the signature
  #      expires. This is copied to the x= tag of the
  #      signature. Setting a value of 0 (the default) omits
  #      the tag from the signature.
  #
  #  Returns: 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
  #
  def pdkim_set_optional(ctx, sign_headers,
      identity, canon_headers, canon_body, bodylength,
      algo, created, expires)
    ruby_pdkim_set_optional(ctx, sign_headers,
      identity, canon_headers, canon_body, bodylength,
      algo, created, expires)
  end

  # ok = pdkim_feed(ctx, data, data_len)
  #
  # (Repeatedly) feed data to the signing algorithm. The message
  # data MUST use CRLF line endings (like SMTP uses on the
  # wire). The data chunks do not need to be a "line" - you
  # can split chunks at arbitrary locations.
  #
  #    data (Ruby String which is also allowed to contain binary)
  #      Pointer to data to feed. Please note that despite
  #      the example given below, this is not necessarily a
  #      C string, i.e., NULL terminated.
  #
  #    data_len
  #      Length of data being fed, in bytes.
  #
  # Returns: 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
  #
  def pdkim_feed(ctx, data, len)
    ruby_pdkim_feed(ctx, data, len)
  end

  # ok = pdkim_feed_finish(ctx)
  #
  # Signal end-of-message and retrieve the signature block.
  #
  # Returns:
  #    ok
  #      0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
  #
  #    signatures (An array of hashes of signatures.)
  #      If the function returns PDKIM_OK, it will return
  #      one or more signatures.
  #
  #      Sign only returns 1 signature, but verify will return 1 signature
  #      for each DKIM header in the email being verified.
  #
  #      Returns an array of hashes (only 1 for sign) with the signatures in them
  #      [
  #        {
  #          "error"=>0, # 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
  #          "signature"=>nil,
  #          "version"=>1,
  #          "algo"=>0,
  #          "canon_headers"=>0,
  #          "canon_body"=>0,
  #          "querymethod"=>0,
  #          "selector"=>"cheezburger",
  #          "domain"=>"duncanthrax.net",
  #          "identity"=>nil,
  #          "created"=>0,
  #          "expires"=>0,
  #          "bodylength"=>-1,
  #          "headernames"=>"Subject:To:From",
  #          "copiedheaders"=>nil,
  #          "sigdata"=>"\xA1\xEDy\x16\xDF\xF1\xF8C\x18\x80\xF8\x1F@\xFCIV&\x0E\xA4\xD5 ...",
  #          "bodyhash"=>"M\x87\xE3_\xE5;T\xD4\x96\x90'I\xEA2\xBF\xCE\x8F\x17\xCD\xEF ...",
  #          "signature_header"=>nil,
  #          "verify_status"=>3,
  #          "verify_ext_status"=>0,
  #          "pubkey"=>{
  #            "version"=>"DKIM1",
  #            "granularity"=>"*",
  #            "hashes"=>nil,
  #            "keytype"=>"rsa",
  #            "srvtype"=>"*",
  #            "notes"=>nil,
  #            "key"=>"0\x81\x9F0\r\x06\t*\x86H\x86\xF7\r\x01\x01\x01\x05\x00\x03\x81\x8D ...",
  #            "testing"=>0,
  #            "no_subdomaining"=>0
  #          }
  #        }
  #      ]
  #
  def pdkim_feed_finish(ctx)
    ruby_pdkim_feed_finish(ctx)
  end

  # pdkim_free_ctx(ctx)
  #
  #  Free all allocated memory blocks referenced from
  #  the context, as well as the context itself.
  #
  #  Don't forget to call this or your application will "leak" memory.
  #
  def pdkim_free_ctx(ctx)
    ruby_pdkim_free_ctx(ctx)
  end

  # ok = pdkim_sign_an_email(mode, domain, selector, rsa_privkey, canon_headers, canon_body, unsigned_message)
  #
  # Call a single function to sign an email message.
  #
  #    mode
  #      PDKIM_INPUT_NORMAL or PDKIM_INPUT_SMTP. When SMTP
  #      input is used, the lib will deflate double-dots at
  #      the start of atline to a single dot, and it will
  #      stop processing input when a line with and single
  #      dot is received (Excess input will simply be ignored).
  #
  #    domain
  #      The domain to sign as. This value will land in the
  #      d= tag of the signature. For example, if the MAIL FROM
  #      address is joe@mail.example.com, the domain is
  #      example.com.
  #
  #    selector
  #      The selector string to use. This value will land in
  #      the s= tag of the signature. For example, if the DNS DKIM TXT
  #      record contains 2015may._domainkey.example.com, the selector
  #      is 2015may.
  #
  #    rsa_privkey
  #      The private RSA key, in ASCII armor. It MUST NOT be
  #      encrypted. For example, in the sample used for this gem,
  #      the private key is: RSA_PRIVKEY:
  #      -----BEGIN RSA PRIVATE KEY-----
  #      MIICXQIBAAKBgQC5+utIbbfbpssvW0TboF73Seos+1ijdPFGwc/z8Yu12cpjBvRb
  #      ...
  #      FA0nM8cHuN/VLKjjcrJUK47lZEOsjLv+qTl0i0Lp6giq
  #      -----END RSA PRIVATE KEY-----
  #
  #    canon_headers (default PDKIM_CANON_SIMPLE)
  #      Canonicalization algorithm to use for headers. One
  #      of PDKIM_CANON_SIMPLE or PDKIM_CANON_RELAXED.
  #
  #    canon_body (default PDKIM_CANON_SIMPLE)
  #      Canonicalization algorithm to use for the body. One
  #      of PDKIM_CANON_SIMPLE or PDKIM_CANON_RELAXED.
  #
  #    unsigned_message
  #      An array of lines containing the email. The message
  #      data array MUST NOT use CRLF line endings, but each line
  #      is assumed to end with a CRLF (like SMTP uses on the
  #      wire). The lines may be of arbitrary length. A line oriented
  #      format was chosen because it's the "natural" way
  #      of formatting the data for Ruby.
  #
  # Returns: an array of 2 elements: [success_code, message]
  #     if successful, returns 0 (PDKIM_OK) and the signed_message
  #     if unsuccessful, returns a PDKIM_ERR_* constant and nil
  #
  def pdkim_sign_an_email(mode, domain, selector, rsa_privkey, canon_headers, canon_body, unsigned_message)
    ctx = pdkim_init_sign(mode, domain, selector, rsa_privkey)
    return [PDKIM_FAIL, verify_counts] if ctx==0
    ok = pdkim_set_optional(ctx, nil, nil, canon_headers, canon_body, -1, PDKIM_ALGO_RSA_SHA256, 0, 0)
    if ok!=PDKIM_OK
      pdkim_free_ctx(ctx)
      return [ok, nil]
    end
    unsigned_message.each do |line|
      ok = pdkim_feed(ctx, line+CRLF, line.length+2)
      if ok!=PDKIM_OK
        pdkim_free_ctx(ctx)
        return [ok, nil]
      end
    end
    signatures = pdkim_feed_finish(ctx)
    pdkim_free_ctx(ctx)
    return [PDKIM_ERR_RSA_SIGNING, nil] if signatures.empty?
    signature = signatures[0][:signature]
    signed_message = [signature]
    signed_message.concat(unsigned_message)
    return [PDKIM_OK, signed_message]
  end

  # ok = verify_an_email(mode, signed_message, sym_domain_lookup)
  #
  # Call a single function to sign an email message.
  #
  #    mode
  #      PDKIM_INPUT_NORMAL or PDKIM_INPUT_SMTP. When SMTP
  #      input is used, the lib will deflate double-dots at
  #      the start of atline to a single dot, and it will
  #      stop processing input when a line with and single
  #      dot is received (Excess input will simply be ignored).
  #
  #    signed_message
  #      An array of lines containing the email preceeded by a
  #      DKIM header that was generated by a signing process. The message
  #      data array MUST NOT contain CRLF line endings; instead, each line
  #      will have a CRLF added here. The lines may be of arbitrary
  #      length. A line oriented format was chosen because it's
  #      the "natural" way of formatting the data for Ruby.
  #
  #    sym_domain_lookup (OPTIONAL)
  #      A symbolic name of the method to use for private key lookups.
  #      If this parameter is not given, it defaults to :pdkim_dkim_public_key_lookup
  #      which is the built-in lookup function.
  #
  # Returns:
  #    ok
  #      0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
  #
  #    signatures (An array of hashes of signatures.)
  #      If the function returns PDKIM_OK, it will return
  #      one or more signatures.
  #
  def pdkim_verify_an_email(mode, signed_message, sym_domain_lookup=:pdkim_dkim_public_key_lookup)
    ctx = pdkim_init_verify(mode) do |name|
      send(sym_domain_lookup, name)
    end
    return [PDKIM_FAIL, verify_counts] if ctx==0
    ok = PDKIM_FAIL
    signed_message.each do |line|
      ok = pdkim_feed(ctx, line+CRLF, line.length+2)
      if ok!=PDKIM_OK
        pdkim_free_ctx(ctx)
        return [ok, verify_counts]
      end
    end
    signatures = pdkim_feed_finish(ctx)
    pdkim_free_ctx(ctx)
    return ok, signatures
  end

  # key = pdkim_dkim_public_key_lookup(name)
  #
  # This method retrieves the public key from the domain's
  # website's DNS records, if any. If it fails, it will return
  # "nil" which will cause the validation to fail with 
  # PDKIM_VERIFY_FAIL.
  #
  #    name
  #      The name to be looked up by the resolver. It has the form:
  #      selector._domainkey.domain.com (org, biz, us, gov, etc.)
  #      the name will be properly formatted if this method is
  #      called from the block in pdkim_init_verify.
  #
  # Returns: The DKIM public key for the domain in 'name' or nil
  #
  def pdkim_dkim_public_key_lookup(name)
    records = [];
    Resolv::DNS.open { |dns| records = dns.getresources(name, Resolv::DNS::Resource::IN::TXT) }
    if records.empty? then nil else records[0].strings.join("") end
  end

end
