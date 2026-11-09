import pytest
from vmssh.core.exceptions import ValidationError
from vmssh.utils.validators import validate_alias, validate_host, validate_port, validate_username


def test_valid_inputs():
    assert validate_host("192.0.2.132") == "192.0.2.132"
    assert validate_host("lab.example.com") == "lab.example.com"
    assert validate_username("testuser") == "testuser"
    assert validate_alias("ubuntu-vm") == "ubuntu-vm"
    assert validate_port("2222") == 2222


@pytest.mark.parametrize("value", ["", "bad host", "a;touch /tmp/x", "$(id)"])
def test_rejects_bad_host(value):
    with pytest.raises(ValidationError):
        validate_host(value)


def test_rejects_bad_username_and_alias():
    with pytest.raises(ValidationError): validate_username("root;id")
    with pytest.raises(ValidationError): validate_alias("bad alias")
    with pytest.raises(ValidationError): validate_port(70000)
