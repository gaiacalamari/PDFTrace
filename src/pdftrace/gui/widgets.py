"""Reusable widgets: a sortable, filterable, exportable table and helpers."""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Sequence
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

RowColor = Callable[[Sequence[Any]], QColor | None]
Index = QModelIndex | QPersistentModelIndex


def display(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        return ", ".join(display(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def sort_key(value: Any) -> Any:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    return display(value).casefold()


class RecordModel(QAbstractTableModel):
    """Rows of raw values; display strings are derived, sorting uses raw values."""

    def __init__(self, headers: Sequence[str]) -> None:
        super().__init__()
        self.headers = list(headers)
        self.rows: list[list[Any]] = []
        self.row_color: RowColor | None = None

    def set_rows(self, rows: Sequence[Sequence[Any]]) -> None:
        self.beginResetModel()
        self.rows = [list(r) for r in rows]
        self.endResetModel()

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        value = self.rows[index.row()][index.column()]
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            text = display(value)
            return text if role == Qt.ItemDataRole.DisplayRole or len(text) > 40 else None
        if role == Qt.ItemDataRole.UserRole:
            return sort_key(value)
        if role == Qt.ItemDataRole.BackgroundRole and self.row_color:
            return self.row_color(self.rows[index.row()])
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return None


class RecordTable(QWidget):
    """Table with search box, sorting, context menu (copy) and CSV/JSON export."""

    row_selected = Signal(int)

    def __init__(
        self, headers: Sequence[str], export_name: str = "table", parent: QWidget | None = None, searchable: bool = True
    ) -> None:
        super().__init__(parent)
        self.export_name = export_name
        self.model = RecordModel(headers)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.view.setAlternatingRowColors(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.view.setWordWrap(False)
        self.view.verticalHeader().setVisible(False)
        header = self.view.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._menu)
        self.view.selectionModel().currentRowChanged.connect(self._current_changed)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.proxy.setFilterFixedString)
        self.count = QLabel()
        self.count.setObjectName("muted")
        csv_btn, json_btn = QPushButton("Export CSV"), QPushButton("Export JSON")
        csv_btn.clicked.connect(lambda: self.export("csv"))
        json_btn.clicked.connect(lambda: self.export("json"))

        bar = QHBoxLayout()
        if searchable:
            bar.addWidget(self.search, 1)
        else:
            bar.addStretch(1)
        bar.addWidget(self.count)
        bar.addWidget(csv_btn)
        bar.addWidget(json_btn)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(bar)
        layout.addWidget(self.view)
        self.proxy.rowsInserted.connect(self._update_count)
        self.proxy.modelReset.connect(self._update_count)
        self.proxy.layoutChanged.connect(self._update_count)
        self.search.textChanged.connect(self._update_count)

    def set_rows(self, rows: Sequence[Sequence[Any]], row_color: RowColor | None = None) -> None:
        self.model.row_color = row_color
        self.model.set_rows(rows)
        self.proxy.sort(-1)
        self.view.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.view.resizeColumnsToContents()
        for col in range(self.model.columnCount()):
            if self.view.columnWidth(col) > 420:
                self.view.setColumnWidth(col, 420)
        self._update_count()

    def _update_count(self, *_: Any) -> None:
        self.count.setText(f"{self.proxy.rowCount()} / {self.model.rowCount()}")

    def _current_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if current.isValid():
            self.row_selected.emit(self.proxy.mapToSource(current).row())

    def selected_source_rows(self) -> list[int]:
        return sorted({self.proxy.mapToSource(i).row() for i in self.view.selectionModel().selectedRows()})

    def visible_rows(self) -> list[list[Any]]:
        return [
            self.model.rows[self.proxy.mapToSource(self.proxy.index(r, 0)).row()] for r in range(self.proxy.rowCount())
        ]

    def _menu(self, pos: Any) -> None:
        index = self.view.indexAt(pos)
        menu = QMenu(self)
        if index.isValid():
            menu.addAction("Copy value", lambda: self._copy(display(self.proxy.data(index))))
            menu.addAction(
                "Copy row",
                lambda: self._copy(self._tsv([self.model.rows[self.proxy.mapToSource(index).row()]], header=False)),
            )
        menu.addAction("Copy visible rows (TSV)", lambda: self._copy(self._tsv(self.visible_rows())))
        menu.addSeparator()
        menu.addAction("Export CSV…", lambda: self.export("csv"))
        menu.addAction("Export JSON…", lambda: self.export("json"))
        menu.exec(self.view.viewport().mapToGlobal(pos))

    @staticmethod
    def _copy(text: str) -> None:
        QGuiApplication.clipboard().setText(text)

    def _tsv(self, rows: Sequence[Sequence[Any]], header: bool = True) -> str:
        lines = ["\t".join(self.model.headers)] if header else []
        lines += ["\t".join(display(v).replace("\t", " ") for v in row) for row in rows]
        return "\n".join(lines)

    def export(self, kind: str) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, f"Export {kind.upper()}", f"{self.export_name}.{kind}", f"{kind.upper()} (*.{kind})"
        )
        if not path:
            return
        rows = self.visible_rows()
        if kind == "csv":
            with open(path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(self.model.headers)
                for row in rows:
                    text = [display(v) for v in row]
                    writer.writerow(["'" + t if t[:1] in "=+-@" else t for t in text])
        else:
            data = [{h: v for h, v in zip(self.model.headers, row, strict=False)} for row in rows]
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle, ensure_ascii=False, indent=2, default=str)


def form(pairs: Sequence[tuple[str, Any]], selectable: bool = True) -> QWidget:
    """A read-only label/value form."""
    widget = QWidget()
    layout = QFormLayout(widget)
    layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
    for key, value in pairs:
        label = QLabel(display(value) or "—")
        label.setWordWrap(True)
        if selectable:
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        muted = QLabel(key)
        muted.setObjectName("muted")
        layout.addRow(muted, label)
    return widget


def title(text: str, subtitle: str | None = None) -> QWidget:
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 6)
    head = QLabel(text)
    head.setObjectName("h1")
    layout.addWidget(head)
    if subtitle:
        sub = QLabel(subtitle)
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        layout.addWidget(sub)
    return widget
