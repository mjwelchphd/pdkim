#include <ruby.h>
#include "pdkim1.h"
#include <stdlib.h>

/* These are, with the exception of 'object_ruby_pdkim_init_verify' and it's callback
 * method 'query_dns_text', just glue routines for the C PDKIM library. */
 
static VALUE pdkim_request_public_key = (VALUE)NULL;
 
static VALUE object_ruby_pdkim_init_sign(VALUE rb_self, VALUE rb_mode, VALUE rb_domain, VALUE rb_selector, VALUE rb_rsa_privkey) {
  int input_type = FIX2INT(rb_mode);
  char* domain = StringValueCStr(rb_domain);
  char* selector = StringValueCStr(rb_selector);
  char* rsa_privkey = StringValueCStr(rb_rsa_privkey);
  pdkim_ctx* ctx = pdkim_init_sign(
    input_type, // Input type
    domain,     // Domain
    selector,   // Selector
    rsa_privkey // Private RSA key
  );
  return LONG2FIX((long)ctx);
}

/* This callback activates the user's 'pdkim_init_verify' block to allow the user to lookup the domain's private key. */
static int query_dns_text(char *name, char *answer) {
  /* This mockup function was intended to encapulate the method to lookup
   * the private key on the domain's webite, but Ruby uses a block on the
   * 'pdkim_init_verify' call. This method is another glue routine. */
  VALUE rb_answer = rb_funcall(pdkim_request_public_key, rb_intern("call"), 1, rb_str_new2(name));
  if (NIL_P(rb_answer))
    return PDKIM_ERR_RSA_PRIVKEY;
  strcpy(answer,StringValueCStr(rb_answer));
  return PDKIM_OK;
}

static VALUE object_ruby_pdkim_init_verify(VALUE rb_self, VALUE rb_state) {
  int state = FIX2INT(rb_state);
  pdkim_ctx* ctx;
  rb_need_block();
  ctx = pdkim_init_verify(state, &query_dns_text);
  // This is the block associated with the 'ruby_pdkim_init_verify' call
  // in 'pdkim_init_verify' in 'pdkimlib' -- I store it in a global
  // variable because there is no other way to get it to the callback method,
  // which is defined here, but used in 'ruby_pdkim_feed_finish' -- I
  // didn't want to modify the source code of the PDKIM itself
  pdkim_request_public_key = rb_block_proc();
  return LONG2FIX((long)ctx);
}

/* This method checks the argument for int or String, and uses that to open the debugging output file. */
static VALUE object_ruby_pdkim_set_debug_stream(VALUE rb_self, VALUE rb_ctx, VALUE rb_file_id) {
  pdkim_ctx* ctx = (pdkim_ctx*)FIX2LONG(rb_ctx);
  FILE *debug;
  if RB_TYPE_P(rb_file_id, T_STRING) {
    debug = fopen(StringValueCStr(rb_file_id),"a");
    if (debug==NULL) return Qfalse;
    pdkim_set_debug_stream(ctx,debug);
    return Qtrue;
  }
  else if RB_TYPE_P(rb_file_id, T_FIXNUM) {
    debug = fdopen(FIX2INT(rb_file_id),"a");
    pdkim_set_debug_stream(ctx,debug);
    return Qtrue;
  }
  else return Qfalse;
}

// This method returns a NULL or a C String, depending on the object type
static char* string_or_nil(VALUE obj) {
  if (NIL_P(obj)) return NULL;
  Check_Type(obj, T_STRING);
  return StringValueCStr(obj);
}

//  Returns: 0 (PDKIM_OK) for success or a PDKIM_ERR_* constant
static VALUE object_ruby_pdkim_set_optional(VALUE rb_self, VALUE rb_ctx, VALUE rb_sign_headers,
    VALUE rb_identity, VALUE rb_canon_headers, VALUE rb_canon_body, VALUE rb_bodylength,
    VALUE rb_algo, VALUE rb_created, VALUE rb_expires) {
  pdkim_ctx* ctx = (pdkim_ctx*)FIX2LONG(rb_ctx);
  char* sign_headers = string_or_nil(rb_sign_headers);
  char* identity = string_or_nil(rb_identity);
  int canon_headers = FIX2INT(rb_canon_headers);
  int canon_body = FIX2INT(rb_canon_body);
  long bodylength = FIX2LONG(rb_bodylength);
  int algo = FIX2INT(rb_algo);
  unsigned long created = FIX2LONG(rb_created);
  unsigned long expires = FIX2LONG(rb_expires);
  int ok = pdkim_set_optional(ctx, sign_headers, identity, canon_headers, canon_body, bodylength, algo, created, expires);

  return LONG2FIX(ok);
}

static VALUE object_ruby_pdkim_feed(VALUE rb_self, VALUE rb_ctx, VALUE rb_data, VALUE rb_len) {
  pdkim_ctx* ctx = (pdkim_ctx*)FIX2LONG(rb_ctx);
  char* data = string_or_nil(rb_data);
  long len = FIX2LONG(rb_len);
  int ok = pdkim_feed(ctx, data, len);
  return LONG2FIX(ok);
}

static void hashint(VALUE hash, const char* name, int value) {
  rb_hash_aset(hash, ID2SYM(rb_intern(name)), INT2FIX(value));
}

static void hashlng(VALUE hash, const char* name, long value) {
  rb_hash_aset(hash, ID2SYM(rb_intern(name)), LONG2FIX(value));
}

static void hashstr(VALUE hash, const char* name, char* value) {
  if (value!=NULL) rb_hash_aset(hash, ID2SYM(rb_intern(name)), rb_str_export_locale((rb_str_new2(value))));
  else rb_hash_aset(hash, ID2SYM(rb_intern(name)), Qnil);
}

static void hashbin(VALUE hash, const char* name, char* value, int len) {
  if (len!=0) rb_hash_aset(hash, ID2SYM(rb_intern(name)), rb_str_export_locale((rb_str_new(value, len))));
  else rb_hash_aset(hash, ID2SYM(rb_intern(name)), Qnil);
}

static VALUE object_ruby_pdkim_feed_finish(VALUE rb_self, VALUE rb_ctx) {
  pdkim_ctx* ctx = (pdkim_ctx*)FIX2LONG(rb_ctx);
  pdkim_signature *signature;
  int ok = pdkim_feed_finish(ctx, &signature);
  VALUE pubkey;

  // Here, we create a hash from the return code and the signature, if any.
  // Note that for a verify call, there may be many signatures in the email,
  // and this will return them all.
  VALUE pdkim_signatures = rb_ary_new();
  while (signature!=NULL) {
    VALUE pdkim_signature_hash = rb_hash_new();
    hashint(pdkim_signature_hash, "error", ok);
    hashstr(pdkim_signature_hash, "signature", signature->signature_header);
    hashint(pdkim_signature_hash, "version", signature->version);
    hashint(pdkim_signature_hash, "algo", signature->algo);
    hashint(pdkim_signature_hash, "canon_headers", signature->canon_headers);
    hashint(pdkim_signature_hash, "canon_body", signature->canon_body);
    hashint(pdkim_signature_hash, "querymethod", signature->querymethod);
    hashstr(pdkim_signature_hash, "selector", signature->selector);
    hashstr(pdkim_signature_hash, "domain", signature->domain);
    hashstr(pdkim_signature_hash, "identity", signature->identity);
    hashlng(pdkim_signature_hash, "created", signature->created);
    hashlng(pdkim_signature_hash, "expires", signature->expires);
    hashlng(pdkim_signature_hash, "bodylength", signature->bodylength);
    hashstr(pdkim_signature_hash, "headernames", signature->headernames);
    hashstr(pdkim_signature_hash, "copiedheaders", signature->copiedheaders);
    hashbin(pdkim_signature_hash, "sigdata", signature->sigdata, signature->sigdata_len);
    hashbin(pdkim_signature_hash, "bodyhash", signature->bodyhash, signature->bodyhash_len);
    hashstr(pdkim_signature_hash, "signature_header", signature->signature_header);
    hashlng(pdkim_signature_hash, "verify_status", signature->verify_status);
    hashlng(pdkim_signature_hash, "verify_ext_status", signature->verify_ext_status);

    if (signature->pubkey!=NULL) {
      pubkey = rb_hash_new();
      hashstr(pubkey, "version", signature->pubkey->version);
      hashstr(pubkey, "granularity", signature->pubkey->granularity);
      hashstr(pubkey, "hashes", signature->pubkey->hashes);
      hashstr(pubkey, "keytype", signature->pubkey->keytype);
      hashstr(pubkey, "srvtype", signature->pubkey->srvtype);
      hashstr(pubkey, "notes", signature->pubkey->notes);
      hashbin(pubkey, "key", signature->pubkey->key, signature->pubkey->key_len);
      hashint(pubkey, "testing", signature->pubkey->testing);
      hashint(pubkey, "no_subdomaining", signature->pubkey->no_subdomaining);
    } else pubkey = Qnil;
    rb_hash_aset(pdkim_signature_hash, ID2SYM(rb_intern("pubkey")), pubkey);

    rb_ary_push(pdkim_signatures, pdkim_signature_hash);
    signature = signature->next;
  }

  return pdkim_signatures;
}

static VALUE object_ruby_pdkim_free_ctx(VALUE rb_self, VALUE rb_ctx) {
  pdkim_free_ctx((pdkim_ctx*)FIX2LONG(rb_ctx));
  return Qnil;
}

// Ruby setup
void Init_pdkimglue() {
  //Function success & error codes
  rb_define_global_const("PDKIM_OK", LONG2FIX(PDKIM_OK));
  rb_define_global_const("PDKIM_FAIL", LONG2FIX(PDKIM_FAIL));
  rb_define_global_const("PDKIM_ERR_OOM", LONG2FIX(PDKIM_ERR_OOM));
  rb_define_global_const("PDKIM_ERR_RSA_PRIVKEY", LONG2FIX(PDKIM_ERR_RSA_PRIVKEY));

  rb_define_global_const("PDKIM_ERR_RSA_SIGNING", LONG2FIX(PDKIM_ERR_RSA_SIGNING));
  rb_define_global_const("PDKIM_ERR_LONG_LINE", LONG2FIX(PDKIM_ERR_LONG_LINE));
  rb_define_global_const("PDKIM_ERR_BUFFER_TOO_SMALL", LONG2FIX(PDKIM_ERR_BUFFER_TOO_SMALL));

  // Context to keep state between all operations
  rb_define_global_const("PDKIM_MODE_SIGN", LONG2FIX(PDKIM_MODE_SIGN));
  rb_define_global_const("PDKIM_MODE_VERIFY", LONG2FIX(PDKIM_MODE_VERIFY));
  rb_define_global_const("PDKIM_INPUT_NORMAL", LONG2FIX(PDKIM_INPUT_NORMAL));
  rb_define_global_const("PDKIM_INPUT_SMTP", LONG2FIX(PDKIM_INPUT_SMTP));

  // Canonicalizations
  rb_define_global_const("PDKIM_CANON_SIMPLE", INT2FIX(PDKIM_CANON_SIMPLE));
  rb_define_global_const("PDKIM_CANON_RELAXED", INT2FIX(PDKIM_CANON_RELAXED));

  // Hash algorithms
  rb_define_global_const("PDKIM_ALGO_RSA_SHA256", INT2FIX(PDKIM_ALGO_RSA_SHA256));
  rb_define_global_const("PDKIM_ALGO_RSA_SHA1", INT2FIX(PDKIM_ALGO_RSA_SHA1));

  // Hash algorithms
  rb_define_global_const("PDKIM_HASH_SHA256", INT2FIX(PDKIM_HASH_SHA256));
  rb_define_global_const("PDKIM_HASH_SHA1", INT2FIX(PDKIM_HASH_SHA1));

  // Main verification status
  rb_define_global_const("PDKIM_VERIFY_NONE", INT2FIX(PDKIM_VERIFY_NONE));
  rb_define_global_const("PDKIM_VERIFY_INVALID", INT2FIX(PDKIM_VERIFY_INVALID));
  rb_define_global_const("PDKIM_VERIFY_FAIL", INT2FIX(PDKIM_VERIFY_FAIL));
  rb_define_global_const("PDKIM_VERIFY_PASS", INT2FIX(PDKIM_VERIFY_PASS));

  // Extended verification status
  rb_define_global_const("PDKIM_VERIFY_FAIL_BODY", INT2FIX(PDKIM_VERIFY_FAIL_BODY));
  rb_define_global_const("PDKIM_VERIFY_FAIL_MESSAGE", INT2FIX(PDKIM_VERIFY_FAIL_MESSAGE));
  rb_define_global_const("PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE", INT2FIX(PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE));
  rb_define_global_const("PDKIM_VERIFY_INVALID_BUFFER_SIZE", INT2FIX(PDKIM_VERIFY_INVALID_BUFFER_SIZE));
  rb_define_global_const("PDKIM_VERIFY_INVALID_PUBKEY_PARSING", INT2FIX(PDKIM_VERIFY_INVALID_PUBKEY_PARSING));

  // Module definitions
  rb_define_method(rb_cObject, "ruby_pdkim_init_sign", object_ruby_pdkim_init_sign, 4);
  rb_define_method(rb_cObject, "ruby_pdkim_init_verify", object_ruby_pdkim_init_verify, 1);
  rb_define_method(rb_cObject, "ruby_pdkim_set_debug_stream", object_ruby_pdkim_set_debug_stream, 2);
  rb_define_method(rb_cObject, "ruby_pdkim_set_optional", object_ruby_pdkim_set_optional, 9);
  rb_define_method(rb_cObject, "ruby_pdkim_feed", object_ruby_pdkim_feed, 3);
  rb_define_method(rb_cObject, "ruby_pdkim_feed_finish", object_ruby_pdkim_feed_finish, 1);
  rb_define_method(rb_cObject, "ruby_pdkim_free_ctx", object_ruby_pdkim_free_ctx, 1);
}
