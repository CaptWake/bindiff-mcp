"""Errors raised by the BinDiff MCP pipeline and mapped to MCP tool errors."""

from __future__ import annotations


class BindiffMcpError(Exception):
    """Base class for failures that are reported back to the MCP client."""


class ExportError(BindiffMcpError):
    """A binary could not be exported to the BinExport format."""


class DiffError(BindiffMcpError):
    """Two BinExport files could not be diffed, or the diff could not be read."""
