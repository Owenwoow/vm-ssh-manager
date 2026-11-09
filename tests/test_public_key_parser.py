from vmssh.core.public_key_deployer import key_identity


def test_key_identity_plain_and_options():
    line = "ssh-ed25519 QUJDREVGRw== windows-vm-key"
    assert key_identity(line) == ("ssh-ed25519", "QUJDREVGRw==")
    optioned = 'from="192.0.2.0/24",no-agent-forwarding ssh-ed25519 QUJDREVGRw== test'
    assert key_identity(optioned) == ("ssh-ed25519", "QUJDREVGRw==")
    assert key_identity("# comment") is None
