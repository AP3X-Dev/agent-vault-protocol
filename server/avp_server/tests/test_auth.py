from avp_server.auth import new_token, token_sha256, hash_token, verify_token

def test_token_hashing():
    tok = new_token("t_")
    sha = token_sha256(tok)
    assert len(sha) == 64
    h = hash_token(tok)
    assert verify_token(tok, h)
    assert not verify_token(tok + "x", h)
