from vmssh.core.sudo_manager import sudoers_content


def test_sudoers_content():
    assert sudoers_content("testuser") == "testuser ALL=(ALL:ALL) NOPASSWD: ALL\n"
