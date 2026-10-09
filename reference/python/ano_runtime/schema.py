from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from .errors import ANOError


class SchemaCatalog:
    def __init__(self, schema_directory: str | Path) -> None:
        self.schema_directory = Path(schema_directory)
        self.schemas: dict[str, dict[str, Any]] = {}
        self.registry = Registry()
        for path in sorted(self.schema_directory.glob("*.schema.json")):
            with path.open("r", encoding="utf-8") as handle:
                schema = json.load(handle)
            schema_id = schema.get("$id")
            if not schema_id:
                raise ANOError("SCHEMA_INVALID", f"schema has no $id: {path.name}")
            name = path.name.removesuffix(".schema.json")
            self.schemas[name] = schema
            self.registry = self.registry.with_resource(
                str(schema_id), Resource.from_contents(schema)
            )

    def check_all(self) -> None:
        for schema in self.schemas.values():
            Draft202012Validator.check_schema(schema)

    def validate(self, schema_name: str, instance: Any) -> None:
        try:
            schema = self.schemas[schema_name]
        except KeyError as exc:
            raise ANOError("SCHEMA_UNKNOWN", f"unknown schema: {schema_name}") from exc
        validator = Draft202012Validator(
            schema,
            registry=self.registry,
            format_checker=FormatChecker(),
        )
        try:
            validator.validate(instance)
        except ValidationError as exc:
            path = ".".join(str(part) for part in exc.absolute_path) or "$"
            raise ANOError("SCHEMA_INVALID", f"{schema_name} at {path}: {exc.message}") from exc

