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
  #      d= tag of the signature.
  #
  #    selector
  #      The selector string to use. This value will land in
  #      the s= tag of the signature.
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
  #      The lib does not include a DNS resolver, so you need
  #      to provide that yourself. If you develop an application
  #      that deals with email, you'll probably have something anyway.
  #
  # Returns: A freshly allocated ctx (context)
  #
  def pdkim_init_verify(state)
    raise ArgumentError.new("pdkim_init_verify") if !block_given?
    ruby_pdkim_init_verify(state) do |name|
      r = yield(name)
    end
  end

  # pdkim_set_debug_stream(ctx, file_name)
  # pdkim_set_debug_stream(ctx, file_number)
  #
  # Set up debugging stream.
  #
  # When PDKIM was compiled with DEBUG defined (which is the
  # recommended default), you can set up a stream where it
  # sends debug output to. If you don't set a debug
  # stream, no debug output is generated.
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
  #      C string.
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
  #    pdkim_signature **signature
  #      Pass in a pointer to a pdkim_signature pointer.
  #      If the function returns PDKIM_OK, it will be set
  #      up to point to a freshly allocated pdkim_signature
  #      block. See pdkim.h for documentation on what that
  #      block contains. Hint: Most implementations will
  #      simply want to retrieve a ready-to-use
  #      DKIM-Signature header, which can be found in
  #      *signature->signature_header. See the code below.
  #
  # Returns: An array of hashes (only 1 for sign) with the signatures in them
  #
  #[
  #  {
  #    "error"=>0, # 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
  #    "signature"=>nil,
  #    "version"=>1,
  #    "algo"=>0,
  #    "canon_headers"=>0,
  #    "canon_body"=>0,
  #    "querymethod"=>0,
  #    "selector"=>"cheezburger",
  #    "domain"=>"duncanthrax.net",
  #    "identity"=>nil,
  #    "created"=>0,
  #    "expires"=>0,
  #    "bodylength"=>-1,
  #    "headernames"=>"Subject:To:From",
  #    "copiedheaders"=>nil,
  #    "sigdata"=>"\xA1\xEDy\x16\xDF\xF1\xF8C\x18\x80\xF8\x1F@\xFCIV&\x0E\xA4\xD5 ...",
  #    "bodyhash"=>"M\x87\xE3_\xE5;T\xD4\x96\x90'I\xEA2\xBF\xCE\x8F\x17\xCD\xEF ...",
  #    "signature_header"=>nil,
  #    "verify_status"=>3,
  #    "verify_ext_status"=>0,
  #    "pubkey"=>{
  #      "version"=>"DKIM1",
  #      "granularity"=>"*",
  #      "hashes"=>nil,
  #      "keytype"=>"rsa",
  #      "srvtype"=>"*",
  #      "notes"=>nil,
  #      "key"=>"0\x81\x9F0\r\x06\t*\x86H\x86\xF7\r\x01\x01\x01\x05\x00\x03\x81\x8D ...",
  #      "testing"=>0,
  #      "no_subdomaining"=>0
  #    }
  #  }
  #]
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

  def pdkim_sign_an_email(mode, domain, selector, rsa_privkey, canon_headers, canon_body, message)
    ctx = pdkim_init_sign(mode, domain, selector, rsa_privkey)
    ok = pdkim_set_optional(ctx, nil, nil, canon_headers, canon_body, -1, PDKIM_ALGO_RSA_SHA256, 0, 0)
    message.each do |line| 
      ok = pdkim_feed(ctx, line, line.length)
    end
    signatures = pdkim_feed_finish(ctx)
    email = signatures[0][:signature] + CRLF + message.join("")
    pdkim_free_ctx(ctx)
    return email
  end

  def pdkim_verify_an_email(mode, email, sym_domain_lookup=:pdkim_dkim_public_key_lookup)
    ctx = pdkim_init_verify(mode) do |name|
      send(sym_domain_lookup, name)
    end
    ok = pdkim_feed(ctx, email, email.length)
    signatures = pdkim_feed_finish(ctx)
    verify_counts = [0, 0, 0, 0]
    signatures.each do |signature|
      verify_counts[signature[:verify_status]] += 1
    end
    pdkim_free_ctx(ctx)
    return verify_counts
  end

  def pdkim_dkim_public_key_lookup(name)
    records = [];
    Resolv::DNS.open { |dns| records = dns.getresources(name, Resolv::DNS::Resource::IN::TXT) }
    ret = (if records.empty? then nil else records[0].strings[0] end)
  end

end
