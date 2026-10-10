"""Regression tests for axis A3 capability inference.

The reported capability distribution in Chapter 5 depends on these patterns, so
they are pinned here. The first test guards the specific defect the original
implementation had: it tokenised the hint prose itself, so filler words such as
"tool", "description" and "schema" matched almost every description.
"""
from cym500.classification.rules import (
    infer_scope_from_description,
    infer_scope_from_schema,
)
from cym500.common.schema import Scope


# --- the defect that motivated the re-specification -------------------------

def test_filler_words_do_not_match():
    for text in (
        "A tool description.",
        "This tool returns a schema.",
        "Describes the tool and its input schema.",
        "Mentions nothing dangerous at all.",
    ):
        assert infer_scope_from_description(text) == set(), text


def test_substring_collisions_do_not_fire():
    # The name-capability calibration episode: these must not match exec/kill.
    assert Scope.EXEC not in infer_scope_from_description("Performs execution planning")
    assert Scope.PROCESS_CONTROL not in infer_scope_from_description("Lists user skills")


# --- positive cases ---------------------------------------------------------

def test_fs_read_requires_verb_and_filesystem_noun():
    assert infer_scope_from_description("Read the contents of a file") == {Scope.FS_READ}
    # A read verb with no filesystem noun is not filesystem reach.
    assert infer_scope_from_description("Read the user's mood") == set()


def test_fs_write_detected():
    assert Scope.FS_WRITE in infer_scope_from_description(
        "Save the result to a file on disk"
    )


def test_network_egress_detected():
    assert Scope.NETWORK_EGRESS in infer_scope_from_description(
        "Fetch a document over https"
    )


def test_exec_detected():
    assert Scope.EXEC in infer_scope_from_description("Execute a shell command")


def test_secrets_access_detected():
    assert Scope.SECRETS_ACCESS in infer_scope_from_description(
        "Reads the API key from an environment variable"
    )


def test_database_detected():
    assert Scope.DATABASE in infer_scope_from_description("Runs a SQL query on postgres")


def test_process_control_detected():
    assert Scope.PROCESS_CONTROL in infer_scope_from_description(
        "Terminate a running process with sigterm"
    )


def test_multiple_scopes_can_co_occur():
    got = infer_scope_from_description(
        "Execute a shell command and save the output to a file"
    )
    assert {Scope.EXEC, Scope.FS_WRITE} <= got


# --- schema route (deterministic) -------------------------------------------

def test_path_property_evidences_fs_read():
    assert infer_scope_from_schema(
        {"properties": {"path": {"type": "string"}}}
    ) == {Scope.FS_READ}


def test_path_property_name_variants():
    for key in ("file_path", "filePath".lower(), "directory", "folder", "file-path"):
        assert infer_scope_from_schema({"properties": {key: {}}}) == {Scope.FS_READ}


def test_unrelated_property_names_do_not_fire():
    assert infer_scope_from_schema({"properties": {"query": {}, "limit": {}}}) == set()


def test_malformed_schema_is_safe():
    assert infer_scope_from_schema(None) == set()
    assert infer_scope_from_schema({"properties": "nope"}) == set()
    assert infer_scope_from_schema({}) == set()


def test_empty_description_is_empty_set():
    assert infer_scope_from_description(None) == set()
    assert infer_scope_from_description("") == set()
