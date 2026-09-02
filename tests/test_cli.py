from coretrace_python.cli import main


def test_cli_requires_an_action(tmp_path, capsys) -> None:
    source = tmp_path / "empty.py"
    source.write_text("", encoding="utf-8")
    assert main([str(source)]) == 2
    assert "no action selected" in capsys.readouterr().err

