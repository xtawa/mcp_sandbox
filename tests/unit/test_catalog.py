from mcp_sandbox.mcp_registry.catalog import Catalog, InstalledMCP


def test_register_and_get(tmp_path):
    cat = Catalog(tmp_path / "cat.db")
    mcp = InstalledMCP(
        name="foo", source="pip://mcp-server-foo@1.0.0", version="1.0.0",
        venv_path=str(tmp_path / "venv"), entrypoint="mcp-server-foo",
        status="installed", sha256="abc",
    )
    cat.register(mcp)
    got = cat.get("foo")
    assert got == mcp
    assert got.status == "installed"


def test_list_returns_all(tmp_path):
    cat = Catalog(tmp_path / "cat.db")
    cat.register(InstalledMCP(name="a", source="pip://a", version="1", venv_path="/v",
                              entrypoint="a", status="installed", sha256="x"))
    cat.register(InstalledMCP(name="b", source="pip://b", version="2", venv_path="/w",
                              entrypoint="b", status="installed", sha256="y"))
    names = sorted(m.name for m in cat.list_all())
    assert names == ["a", "b"]


def test_update_status(tmp_path):
    cat = Catalog(tmp_path / "cat.db")
    cat.register(InstalledMCP(name="a", source="pip://a", version="1", venv_path="/v",
                              entrypoint="a", status="installed", sha256="x"))
    cat.update_status("a", "running")
    assert cat.get("a").status == "running"


def test_remove(tmp_path):
    cat = Catalog(tmp_path / "cat.db")
    cat.register(InstalledMCP(name="a", source="pip://a", version="1", venv_path="/v",
                              entrypoint="a", status="installed", sha256="x"))
    cat.remove("a")
    assert cat.get("a") is None
