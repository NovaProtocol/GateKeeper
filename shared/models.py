from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func, text
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.orm import Mapped, mapped_column, relationship

from shared.db import Base


class Route(Base):
    __tablename__ = "routes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    path: Mapped[str] = mapped_column(String(1024), default="/", server_default="/")
    route_type: Mapped[str] = mapped_column(String(16), default="proxy", server_default="proxy")
    upstream: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    redirect_target: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    redirect_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, default=302, server_default="302")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())


class RuleGroup(Base):
    __tablename__ = "rule_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    domain: Mapped[str] = mapped_column(String(255))
    display_order: Mapped[int] = mapped_column(Integer, index=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())
    rules: Mapped[list[Rule]] = relationship("Rule", back_populates="group", cascade="all, delete-orphan", order_by="Rule.display_order")


class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("rule_groups.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(String(1024))
    action: Mapped[str] = mapped_column(String(32))
    custom_password_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    custom_password_salt: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    allow_ip: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    allow_time: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    rate_limit: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    display_order: Mapped[int] = mapped_column(Integer, index=True)
    #: The group's `/*` catch-all. Exactly one per group, always last, and the
    #: only rule that cannot be deleted or moved. See `shared/backup.py` for the
    #: reading used when a configuration predates the column.
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())
    group: Mapped[RuleGroup] = relationship("RuleGroup", back_populates="rules")


class CustomPage(Base):
    """A body the gateway serves itself, matched by a host-glob/path-glob pattern.

    ``pattern`` holds the whole URL shape (``*.projectnova.download/robots.txt``)
    rather than a host and a path in two columns: a pair would let a row claim a
    host match with no path, and the owner's own description of this feature was
    "anything as long as it matched the url". See :mod:`shared.pages` for the
    glob vocabulary and the precedence rule.
    """

    __tablename__ = "custom_pages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pattern: Mapped[str] = mapped_column(String(1024), unique=True, index=True)
    #: The bytes that are served. `MEDIUMTEXT` on MySQL because plain `TEXT`
    #: there is 64 KiB while the accepted body is larger; SQLite is unbounded
    #: either way, so the variant only keeps the two backends honest.
    body: Mapped[str] = mapped_column(Text().with_variant(MEDIUMTEXT, "mysql"))
    content_type: Mapped[str] = mapped_column(
        String(255), default="text/plain; charset=utf-8", server_default="text/plain; charset=utf-8"
    )
    #: Off switch, mirroring `codes.active`. `nullable=False` is load-bearing:
    #: the gate reads "not False" as active, so a NULL row would show as off in
    #: the panel while still being served.
    active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("1")
    )
    display_order: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class Code(Base):
    __tablename__ = "codes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    label: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())
    last_accessed: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True, index=True)
    action: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    #: The visitor's country, as the tunnel reported it. Country only: no city and
    #: no coordinates are derived from the visitor's own address. Rows written
    #: before this column existed stay NULL and are reported as "Unknown"
    #: rather than guessed at from the address.
    country: Mapped[str | None] = mapped_column(String(2), nullable=True, index=True)
    code_id: Mapped[Optional[int]] = mapped_column(ForeignKey("codes.id"), nullable=True, index=True)
    rule_group_id: Mapped[Optional[int]] = mapped_column(ForeignKey("rule_groups.id"), nullable=True)
    rule_id: Mapped[Optional[int]] = mapped_column(ForeignKey("rules.id"), nullable=True)
    matched_action: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    referer: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    attempted_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
